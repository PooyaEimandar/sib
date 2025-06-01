// RFC 9110-compliant
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HttpStatus {
    // 1xx Informational
    Continue,
    SwitchingProtocols,
    Processing,
    EarlyHints,

    // 2xx Success
    Ok,
    Created,
    Accepted,
    NonAuthoritativeInformation,
    NoContent,
    ResetContent,
    PartialContent,
    MultiStatus,
    AlreadyReported,
    ImUsed,

    // 3xx Redirection
    MultipleChoices,
    MovedPermanently,
    Found,
    SeeOther,
    NotModified,
    UseProxy,
    TemporaryRedirect,
    PermanentRedirect,

    // 4xx Client Error
    BadRequest,
    Unauthorized,
    PaymentRequired,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    NotAcceptable,
    ProxyAuthenticationRequired,
    RequestTimeout,
    Conflict,
    Gone,
    LengthRequired,
    PreconditionFailed,
    PayloadTooLarge,
    UriTooLong,
    UnsupportedMediaType,
    RangeNotSatisfiable,
    ExpectationFailed,
    ImATeapot,
    MisdirectedRequest,
    UnprocessableEntity,
    Locked,
    FailedDependency,
    TooEarly,
    UpgradeRequired,
    PreconditionRequired,
    TooManyRequests,
    RequestHeaderFieldsTooLarge,
    UnavailableForLegalReasons,

    // 5xx Server Error
    InternalServerError,
    NotImplemented,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
    HttpVersionNotSupported,
    VariantAlsoNegotiates,
    InsufficientStorage,
    LoopDetected,
    NotExtended,
    NetworkAuthenticationRequired,
}

impl HttpStatus {
    pub fn as_parts(&self) -> (&'static str, &'static str) {
        use HttpStatus::*;
        match self {
            // 1xx
            Continue => ("100", "Continue"),
            SwitchingProtocols => ("101", "Switching Protocols"),
            Processing => ("102", "Processing"),
            EarlyHints => ("103", "Early Hints"),

            // 2xx
            Ok => ("200", "OK"),
            Created => ("201", "Created"),
            Accepted => ("202", "Accepted"),
            NonAuthoritativeInformation => ("203", "Non-Authoritative Information"),
            NoContent => ("204", "No Content"),
            ResetContent => ("205", "Reset Content"),
            PartialContent => ("206", "Partial Content"),
            MultiStatus => ("207", "Multi-Status"),
            AlreadyReported => ("208", "Already Reported"),
            ImUsed => ("226", "IM Used"),

            // 3xx
            MultipleChoices => ("300", "Multiple Choices"),
            MovedPermanently => ("301", "Moved Permanently"),
            Found => ("302", "Found"),
            SeeOther => ("303", "See Other"),
            NotModified => ("304", "Not Modified"),
            UseProxy => ("305", "Use Proxy"),
            TemporaryRedirect => ("307", "Temporary Redirect"),
            PermanentRedirect => ("308", "Permanent Redirect"),

            // 4xx
            BadRequest => ("400", "Bad Request"),
            Unauthorized => ("401", "Unauthorized"),
            PaymentRequired => ("402", "Payment Required"),
            Forbidden => ("403", "Forbidden"),
            NotFound => ("404", "Not Found"),
            MethodNotAllowed => ("405", "Method Not Allowed"),
            NotAcceptable => ("406", "Not Acceptable"),
            ProxyAuthenticationRequired => ("407", "Proxy Authentication Required"),
            RequestTimeout => ("408", "Request Timeout"),
            Conflict => ("409", "Conflict"),
            Gone => ("410", "Gone"),
            LengthRequired => ("411", "Length Required"),
            PreconditionFailed => ("412", "Precondition Failed"),
            PayloadTooLarge => ("413", "Payload Too Large"),
            UriTooLong => ("414", "URI Too Long"),
            UnsupportedMediaType => ("415", "Unsupported Media Type"),
            RangeNotSatisfiable => ("416", "Range Not Satisfiable"),
            ExpectationFailed => ("417", "Expectation Failed"),
            ImATeapot => ("418", "I'm a teapot"),
            MisdirectedRequest => ("421", "Misdirected Request"),
            UnprocessableEntity => ("422", "Unprocessable Entity"),
            Locked => ("423", "Locked"),
            FailedDependency => ("424", "Failed Dependency"),
            TooEarly => ("425", "Too Early"),
            UpgradeRequired => ("426", "Upgrade Required"),
            PreconditionRequired => ("428", "Precondition Required"),
            TooManyRequests => ("429", "Too Many Requests"),
            RequestHeaderFieldsTooLarge => ("431", "Request Header Fields Too Large"),
            UnavailableForLegalReasons => ("451", "Unavailable For Legal Reasons"),

            // 5xx
            InternalServerError => ("500", "Internal Server Error"),
            NotImplemented => ("501", "Not Implemented"),
            BadGateway => ("502", "Bad Gateway"),
            ServiceUnavailable => ("503", "Service Unavailable"),
            GatewayTimeout => ("504", "Gateway Timeout"),
            HttpVersionNotSupported => ("505", "HTTP Version Not Supported"),
            VariantAlsoNegotiates => ("506", "Variant Also Negotiates"),
            InsufficientStorage => ("507", "Insufficient Storage"),
            LoopDetected => ("508", "Loop Detected"),
            NotExtended => ("510", "Not Extended"),
            NetworkAuthenticationRequired => ("511", "Network Authentication Required"),
        }
    }
}
