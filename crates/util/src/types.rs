// Action argument defines position in PAM stack
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum Actions {
    PREAUTH,
    AUTHSUCC,
    #[default]
    AUTHFAIL,
}