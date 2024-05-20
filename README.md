# pam-authramp
The AuthRamp PAM (Pluggable Authentication Modules) module provides an account lockout mechanism based on the number of authentication failures. It calculates a dynamic delay for subsequent authentication attempts, increasing the delay with each failure to mitigate brute force attacks.

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Threat model](#threat-model)
4. [Contributing](#contributing)
5. [Mentions](#mentions)

## Installation
### RPM
If you're a RPM distribution user, then then pam-authramp can be installed using a binary .rpm file provided in each [release](https://github.com/34N0/pam-authramp/releases).
```bash
sudo rpm -i pam-authramp-<VERSION>.x86_64.rpm
```
### COPR
The module is released in a COPR repository:
```bash
sudo dnf copr enable 34n0s/pam-authramp
sudo dnf install pam-authramp
```

### rpm-ostree
Use a 3rd party tool like [rpm-copr](https://github.com/34N0/rpm-copr) to add the copr repository
```bash
rpm-copr enable 34n0s/pam-authramp
rpm-ostree install pam-authramp
```

### Debian
If you're a Debian user (or a user of a Debian derivative like Ubuntu), then pam-authramp can be installed using a binary .deb file provided in each [release](https://github.com/34N0/pam-authramp/releases).
```bash
sudo dpkg -i pam-authramp_<VERSION>_amd64.deb
```

### Manually
1. Download the latest [release](https://github.com/34N0/pam-authramp/releases).
2. Copy the `libpam_authramp.so` library to the default PAM library directory. The directory varies for different distributions. For example, in current Fedora versions, the path is `/lib64/security`.
3. Add the module library calls to the PAM service stack in `/etc/pam.d`.

## Configuration
### PAM service
Edit the PAM service stacks in '/etc/pam.d'. Add the preauth hook before the authentication module:
```conf
auth        required                                     libpam_authramp.so preauth
```
The actual authentication module needs to be 'sufficient':
```conf
auth        sufficient                                   pam_unix.so
```
Add the authfail hook right after the authentication module:
```conf
auth        [default=die]                                libpam_authramp.so authfail
```
And finally add the module to the top of the account stack:
```conf
account     required                                     libpam_authramp.so
```
### authramp.conf
Create a configuration file under /etc/security/authramp.conf. This is an example configuration:
```toml
# AuthRamp Configuration File
# This file configures the behavior of the AuthRamp PAM module.
#
[Configuration]
# Directory where tally information is stored.
# Each user has a separate file in this directory to track authentication failures.
# tally_dir = /var/run/authramp
#
# Number of allowed free authentication attempts before applying delays.
# During these free tries, the module allows authentication without introducing delays.
# free_tries = 6
#
# Base delay applied to each authentication failure.
# This is the initial delay applied after the free tries are exhausted.
# base_delay_seconds = 30
#
# Multiplier for the delay calculation based on the number of failures.
# The delay for each subsequent failure is calculated as follows:
# delay = ramp_multiplier * (fails - free_tries) * ln(fails - free_tries) + base_delay_seconds
# ramp_multiplier = 50
#
# Even lock out the root user. Enabling this can be dangerous and may result in a total system lockout.
# For auditing purposes, the tally will still be created for the root user, even if this setting is disabled.
# If you plan to enable this feature, make sure there isn't any tally stored under <tally_dir>/root, or you risk immediate lockout.
# even_deny_root = false
#
# Whether the PAM user messages in the login screen should update automatically or not.
# countdown = true
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

### Reset user
The cli uses the reads the same configuration in `authramp.conf`. 
```bash
$ authramp --help

 █████ ██    ████████████   ████████  █████ ███    █████████  
██   ████    ██   ██   ██   ████   ████   ██████  ██████   ██ 
█████████    ██   ██   █████████████ █████████ ████ ████████  
██   ████    ██   ██   ██   ████   ████   ████  ██  ████      
██   ██ ██████    ██   ██   ████   ████   ████      ████

by 34n0@immerda.ch

Usage: authramp [COMMAND]

Commands:
  reset  Reset a locked PAM user
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## Logging
The module and cli generate logs following the PAM module logging style. For instance, the logging entries created during integration tests serve as examples. 
```console
Feb 04 01:42:42 fedora test_pam_auth-501103939372d9d4[89930]: libpam_authramp(test-authramp:auth): PAM_AUTH_ERR: Added tally (7 failures) for the "user" account. Account is locked until 2024-02-04 00:43:12.983474044 UTC.
Feb 04 01:42:42 fedora test_pam_auth-501103939372d9d4[89930]: libpam_authramp(test-authramp:auth): PAM_AUTH_ERR: Account User(1000, user) is getting bounced. Account still locked until 2024-02-04 00:43:12.983474044 UTC
Feb 04 01:43:15 fedora test_pam_auth-501103939372d9d4[89930]: libpam_authramp(test-authramp:auth): PAM_AUTH_ERR: Account User(1000, user) is getting bounced. Account still locked until 2024-02-04 00:43:12.983474044 UTC
Feb 04 01:43:15 fedora test_pam_auth-501103939372d9d4[89930]: libpam_authramp(test-authramp:account): PAM_SUCCESS: Clear tally (7 failures) for the "user" account. Account is unlocked.
Feb 04 01:43:19 fedora test_pam_auth-501103939372d9d4[89930]: libpam_authramp(test-authramp:account): PAM_SUCCESS: Clear tally (1 failures) for the "user" account. Account is unlocked.
```

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

## Mentions
- This project would not have been possible without the work done in the [pam-rs](https://github.com/anowell/pam-rs) crate.
- The Lockout mechanism is inspired by the [GrapheneOS](https://grapheneos.org/faq#security-and-privacy) implementation.
- This Module was developed to fix a PAM DoS vulnerability in [Secureblue](https://github.com/secureblue/secureblue).
