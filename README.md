# pam-authramp
The RampDelay PAM (Pluggable Authentication Modules) module provides an account lockout mechanism based on the number of authentication failures. It calculates a dynamic delay for subsequent authentication attempts, increasing the delay with each failure to mitigate brute force attacks.

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