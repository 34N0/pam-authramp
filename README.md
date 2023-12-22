# pam-authramp
The AuthRamp PAM (Pluggable Authentication Modules) module provides an account lockout mechanism based on the number of authentication failures. It calculates a dynamic delay for subsequent authentication attempts, increasing the delay with each failure to mitigate brute force attacks.

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Threat model](#threat-model)
4. [Contributing](#contributing)

## Installation
1. Copy the `libpam_authramp.so` library to the default PAM library directory. The directory varies for different distributions. For example, in current Fedora versions, the path is `/lib64/security`.
2. Add the module library calls to the PAM service stack in `/etc/pam.d`:
```conf
# Add the preauth parameter before user authentication
auth        required                                     libpam_authramp.so preauth
# Local user password authentication; should be sufficient
auth        sufficient                                   pam_unix.so nullok
# Add the authfail parameter right after user authentication
auth        [default=die]                                libpam_authramp.so authfail

# Add this at the beginning of the account stack
account     required                                     libpam_authramp.so
```
## Configuration
### authramp.conf
Create a configuration file under /etc/security/authramp.conf with the following values:
```ini
[Settings]
tally_dir = /var/run/authramp
free_tries = 6
base_delay_seconds = 30
ramp_multiplier = 50
```
### default delay
The default configuration of this module is very restrictive. The standard delays are:

- 0 to 6 failed attempts: no delay (2 sessions of 3 tries)
- 7th failed attempt: 30-second delay
- 15th failed attempt: 15 minutes delay
- 30th failed attempt: 1-hour delay
- 300th or later failed attempt: 24 hours delay

The formula used to calculate the delay is:
```
f : failedAttempts  
f₀ : freeTries  
r : rampMultiplier  
b : baseDelaySeconds  
delay = r * (f - f₀) * log(f - f₀) + b
```

### tally file
The tally file tracks failed attempts. Per default, it is stored in `/var/run/authramp/<user>`. To reset and unlock any user, simply delete the file.

## Threat Model

The primary objective of pam-authramp is to enhance the security of Linux systems by implementing a dynamic account lockout mechanism based on the number of consecutive failed authentication attempts. This module aims to prevent unauthorized access to user accounts, mitigate brute-force attacks, and provide an additional layer of protection against malicious activities.

### Key Objectives:

1. **Dynamic Lockout:** Implement a flexible account lockout mechanism that adapts to the user's behavior, dynamically adjusting lockout durations based on the number of consecutive authentication failures.

2. **Configurability:** Allow system administrators to configure lockout parameters such as the number of free authentication attempts, base delay duration, and the multiplier for ramping delays. This ensures adaptability to diverse security requirements.

3. **User-Friendly:** Prioritize user experience by avoiding indefinite account lockouts. Temporary lockouts provide a balance between security and accessibility, ensuring users can regain access to their accounts after a defined period.

4. **Compatibility:** Seamlessly integrate with the Linux Pluggable Authentication Module (PAM) framework, allowing easy adoption within various authentication scenarios and user environments.

5. **Usability in Restricted Environments:** Cater to systems with security practices such as disabling the root account. pam-authramp acts as an additional safeguard without the need for a separate system administrator to unlock accounts.

pam-authramp provides a valuable layer of defense against brute-force attacks, but its successful implementation requires careful configuration, compatibility checks, and continuous monitoring. Administrators and users must consider its limitations and conduct thorough testing to ensure it aligns with the security goals of the system.

## Contributing
Contributing is welcomed! Read the [Contributing Guide](CONTRIBUTING.md) and the [CoC](CODE_OF_CONDUCT.md).