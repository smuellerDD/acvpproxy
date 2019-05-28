# Apple macOS Specialities

The ACVP Proxy potentially runs for an extended period of time. The Apple
macOS power nap interferes with the ACVP Proxy. The per-application nap
functionality is already disabled. But the system-global power nap
is not disabled.

If the power nap is active, the ACVP Proxy stalls. Thus, you must disable
the power nap if you want to execute the ACVP Proxy without monitoring
and preventing the power nap to kick in.

To disable the power nap, do the following:

	1. Open the system settings

	2. Open "Energy Saver"

	3. Disable "Power Nap"
