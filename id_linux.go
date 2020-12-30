// +build linux

package machineid

import "os"

const (
	// the environment variable name pointing to the machine id pathname
	ENV_VARNAME = "MACHINE_ID_FILE"

	// dbusPath is the default path for dbus machine id.
	dbusPath = "/var/lib/dbus/machine-id"
	// dbusPathEtc is the default path for dbus machine id located in /etc.
	// Some systems (like Fedora 20) only know this path.
	// Sometimes it's the other way round.
	dbusPathEtc = "/etc/machine-id"
)

// machineID returns the uuid specified at `/var/lib/dbus/machine-id` or `/etc/machine-id`.
// If there is an error reading the files an empty string is returned.
// See https://unix.stackexchange.com/questions/144812/generate-consistent-machine-unique-id
func machineID() (string, error) {
	env_pathname := os.Getenv(ENV_VARNAME)
	id, err := readFirstFile([]string{
		env_pathname, dbusPath, dbusPathEtc,
	})
	if err != nil {
		return "", err
	}
	return trim(string(id)), nil
}
