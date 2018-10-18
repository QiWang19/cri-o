package server

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cri-o/ocicni/pkg/ocicni"
	units "github.com/docker/go-units"
	"github.com/kubernetes-sigs/cri-o/lib/sandbox"
	"github.com/kubernetes-sigs/cri-o/server/metrics"
	"github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runc/libcontainer/devices"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/validate"
	"github.com/pkg/errors"
	"github.com/syndtr/gocapability/capability"
	pb "k8s.io/kubernetes/pkg/kubelet/apis/cri/runtime/v1alpha2"
)

const (
	// According to http://man7.org/linux/man-pages/man5/resolv.conf.5.html:
	// "The search list is currently limited to six domains with a total of 256 characters."
	maxDNSSearches = 6

	maxLabelSize = 4096
)

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func removeFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

func parseDNSOptions(servers, searches, options []string, path string) error {
	nServers := len(servers)
	nSearches := len(searches)
	nOptions := len(options)
	if nServers == 0 && nSearches == 0 && nOptions == 0 {
		return copyFile("/etc/resolv.conf", path)
	}

	if nSearches > maxDNSSearches {
		return fmt.Errorf("DNSOption.Searches has more than 6 domains")
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if nSearches > 0 {
		data := fmt.Sprintf("search %s\n", strings.Join(searches, " "))
		_, err = f.Write([]byte(data))
		if err != nil {
			return err
		}
	}

	if nServers > 0 {
		data := fmt.Sprintf("nameserver %s\n", strings.Join(servers, "\nnameserver "))
		_, err = f.Write([]byte(data))
		if err != nil {
			return err
		}
	}

	if nOptions > 0 {
		data := fmt.Sprintf("options %s\n", strings.Join(options, " "))
		_, err = f.Write([]byte(data))
		if err != nil {
			return err
		}
	}

	return nil
}

func newPodNetwork(sb *sandbox.Sandbox) ocicni.PodNetwork {
	return ocicni.PodNetwork{
		Name:      sb.KubeName(),
		Namespace: sb.Namespace(),
		ID:        sb.ID(),
		NetNS:     sb.NetNsPath(),
	}
}

// inStringSlice checks whether a string is inside a string slice.
// Comparison is case insensitive.
func inStringSlice(ss []string, str string) bool {
	for _, s := range ss {
		if strings.ToLower(s) == strings.ToLower(str) {
			return true
		}
	}
	return false
}

// getOCICapabilitiesList returns a list of all available capabilities.
func getOCICapabilitiesList() []string {
	var caps []string
	for _, cap := range capability.List() {
		if cap > validate.LastCap() {
			continue
		}
		caps = append(caps, "CAP_"+strings.ToUpper(cap.String()))
	}
	return caps
}

func recordOperation(operation string, start time.Time) {
	metrics.CRIOOperations.WithLabelValues(operation).Inc()
	metrics.CRIOOperationsLatency.WithLabelValues(operation).Observe(metrics.SinceInMicroseconds(start))
}

// recordError records error for metric if an error occurred.
func recordError(operation string, err error) {
	if err != nil {
		// TODO(runcom): handle timeout from ctx as well
		metrics.CRIOOperationsErrors.WithLabelValues(operation).Inc()
	}
}

func validateLabels(labels map[string]string) error {
	for k, v := range labels {
		if (len(k) + len(v)) > maxLabelSize {
			if len(k) > 10 {
				k = k[:10]
			}
			return fmt.Errorf("label key and value greater than maximum size (%d bytes), key: %s", maxLabelSize, k)
		}
	}
	return nil
}

func mergeEnvs(imageConfig *v1.Image, kubeEnvs []*pb.KeyValue) []string {
	envs := []string{}
	if kubeEnvs == nil && imageConfig != nil {
		envs = imageConfig.Config.Env
	} else {
		for _, item := range kubeEnvs {
			if item.GetKey() == "" {
				continue
			}
			envs = append(envs, item.GetKey()+"="+item.GetValue())
		}
		if imageConfig != nil {
			for _, imageEnv := range imageConfig.Config.Env {
				var found bool
				parts := strings.SplitN(imageEnv, "=", 2)
				if len(parts) != 2 {
					continue
				}
				imageEnvKey := parts[0]
				if imageEnvKey == "" {
					continue
				}
				for _, kubeEnv := range envs {
					kubeEnvKey := strings.SplitN(kubeEnv, "=", 2)[0]
					if kubeEnvKey == "" {
						continue
					}
					if imageEnvKey == kubeEnvKey {
						found = true
						break
					}
				}
				if !found {
					envs = append(envs, imageEnv)
				}
			}
		}
	}
	return envs
}

// Namespace represents a kernel namespace name.
type Namespace string

const (
	// IpcNamespace is the Linux IPC namespace
	IpcNamespace = Namespace("ipc")

	// NetNamespace is the network namespace
	NetNamespace = Namespace("net")

	// UnknownNamespace is the zero value if no namespace is known
	UnknownNamespace = Namespace("")
)

var namespaces = map[string]Namespace{
	"kernel.sem": IpcNamespace,
}

var prefixNamespaces = map[string]Namespace{
	"kernel.shm": IpcNamespace,
	"kernel.msg": IpcNamespace,
	"fs.mqueue.": IpcNamespace,
	"net.":       NetNamespace,
}

// validateSysctl checks that a sysctl is whitelisted because it is known
// to be namespaced by the Linux kernel.
// The parameters hostNet and hostIPC are used to forbid sysctls for pod sharing the
// respective namespaces with the host. This check is only used on sysctls defined by
// the user in the crio.conf file.
func validateSysctl(sysctl string, hostNet, hostIPC bool) error {
	nsErrorFmt := "%q not allowed with host %s enabled"
	if ns, found := namespaces[sysctl]; found {
		if ns == IpcNamespace && hostIPC {
			return errors.Errorf(nsErrorFmt, sysctl, ns)
		}
		if ns == NetNamespace && hostNet {
			return errors.Errorf(nsErrorFmt, sysctl, ns)
		}
		return nil
	}
	for p, ns := range prefixNamespaces {
		if strings.HasPrefix(sysctl, p) {
			if ns == IpcNamespace && hostIPC {
				return errors.Errorf(nsErrorFmt, sysctl, ns)
			}
			if ns == NetNamespace && hostNet {
				return errors.Errorf(nsErrorFmt, sysctl, ns)
			}
			return nil
		}
	}
	return errors.Errorf("%q not whitelisted", sysctl)
}

type ulimit struct {
	name string
	hard uint64
	soft uint64
}

func getUlimitsFromConfig(config Config) ([]ulimit, error) {
	var ulimits []ulimit
	for _, u := range config.RuntimeConfig.DefaultUlimits {
		ul, err := units.ParseUlimit(u)
		if err != nil {
			return nil, err
		}
		rl, err := ul.GetRlimit()
		if err != nil {
			return nil, err
		}
		// This sucks, but it's the runtime-tools interface
		ulimits = append(ulimits, ulimit{name: "RLIMIT_" + strings.ToUpper(ul.Name), hard: rl.Hard, soft: rl.Soft})
	}
	return ulimits, nil
}

// parseDevice parses device mapping string to a src, dest & permissions string
func parseDevice(device string) (string, string, string, error) { //nolint
	src := ""
	dst := ""
	permissions := "rwm"
	arr := strings.Split(device, ":")
	switch len(arr) {
	case 3:
		if !ValidDeviceMode(arr[2]) {
			return "", "", "", fmt.Errorf("invalid device mode: %s", arr[2])
		}
		permissions = arr[2]
		fallthrough
	case 2:
		if ValidDeviceMode(arr[1]) {
			permissions = arr[1]
		} else {
			if arr[1][0] != '/' {
				return "", "", "", fmt.Errorf("invalid device mode: %s", arr[2])
			}
			dst = arr[1]
		}
		fallthrough
	case 1:
		src = arr[0]
	default:
		return "", "", "", fmt.Errorf("invalid device specification: %s", device)
	}

	if dst == "" {
		dst = src
	}
	return src, dst, permissions, nil
}

// ValidDeviceMode checks if the mode for device is valid or not.
// Valid mode is a composition of r (read), w (write), and m (mknod).
func ValidDeviceMode(mode string) bool {
	var legalDeviceMode = map[rune]bool{
		'r': true,
		'w': true,
		'm': true,
	}
	if mode == "" {
		return false
	}
	for _, c := range mode {
		if !legalDeviceMode[c] {
			return false
		}
		legalDeviceMode[c] = false
	}
	return true
}

func getDevicesFromConfig(config Config) ([]spec.LinuxDevice, error) {
	var linuxdevs []spec.LinuxDevice
	for _, d := range config.RuntimeConfig.AdditionalDevices {
		src, dst, permissions, err := parseDevice(d)
		if err != nil {
			return nil, err
		}
		dev, err := devices.DeviceFromPath(src, permissions)
		if err != nil {
			return nil, errors.Wrapf(err, "%s is not a valid device", src)
		}
		dev.Path = dst
		linuxdev := spec.LinuxDevice{
			Path:     dev.Path,
			Type:     string(dev.Type),
			Major:    dev.Major,
			Minor:    dev.Minor,
			FileMode: &dev.FileMode,
			UID:      &dev.Uid,
			GID:      &dev.Gid,
		}
		linuxdevs = append(linuxdevs, linuxdev)
	}
	return linuxdevs, nil
}
