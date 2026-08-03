#include <errno.h>

#define MAX_ERRNO 4096

const char *const errno_names[MAX_ERRNO] = {
    [0] = "OK",

#ifdef EPERM
    [EPERM] = "EPERM",
#endif
#ifdef ENOENT
    [ENOENT] = "ENOENT",
#endif
#ifdef ESRCH
    [ESRCH] = "ESRCH",
#endif
#ifdef EINTR
    [EINTR] = "EINTR",
#endif
#ifdef EIO
    [EIO] = "EIO",
#endif
#ifdef ENXIO
    [ENXIO] = "ENXIO",
#endif
#ifdef E2BIG
    [E2BIG] = "E2BIG",
#endif
#ifdef ENOEXEC
    [ENOEXEC] = "ENOEXEC",
#endif
#ifdef EBADF
    [EBADF] = "EBADF",
#endif
#ifdef ECHILD
    [ECHILD] = "ECHILD",
#endif
#ifdef EAGAIN
    [EAGAIN] = "EAGAIN",
#endif
#ifdef ENOMEM
    [ENOMEM] = "ENOMEM",
#endif
#ifdef EACCES
    [EACCES] = "EACCES",
#endif
#ifdef EFAULT
    [EFAULT] = "EFAULT",
#endif
#ifdef EBUSY
    [EBUSY] = "EBUSY",
#endif
#ifdef EEXIST
    [EEXIST] = "EEXIST",
#endif
#ifdef EXDEV
    [EXDEV] = "EXDEV",
#endif
#ifdef ENODEV
    [ENODEV] = "ENODEV",
#endif
#ifdef ENOTDIR
    [ENOTDIR] = "ENOTDIR",
#endif
#ifdef EISDIR
    [EISDIR] = "EISDIR",
#endif
#ifdef EINVAL
    [EINVAL] = "EINVAL",
#endif
#ifdef ENFILE
    [ENFILE] = "ENFILE",
#endif
#ifdef EMFILE
    [EMFILE] = "EMFILE",
#endif
#ifdef ENOTTY
    [ENOTTY] = "ENOTTY",
#endif
#ifdef EFBIG
    [EFBIG] = "EFBIG",
#endif
#ifdef ENOSPC
    [ENOSPC] = "ENOSPC",
#endif
#ifdef ESPIPE
    [ESPIPE] = "ESPIPE",
#endif
#ifdef EROFS
    [EROFS] = "EROFS",
#endif
#ifdef EMLINK
    [EMLINK] = "EMLINK",
#endif
#ifdef EPIPE
    [EPIPE] = "EPIPE",
#endif
#ifdef EDOM
    [EDOM] = "EDOM",
#endif
#ifdef ERANGE
    [ERANGE] = "ERANGE",
#endif
#ifdef EDEADLK
    [EDEADLK] = "EDEADLK",
#endif
#ifdef ENAMETOOLONG
    [ENAMETOOLONG] = "ENAMETOOLONG",
#endif
#ifdef ENOLCK
    [ENOLCK] = "ENOLCK",
#endif
#ifdef ENOSYS
    [ENOSYS] = "ENOSYS",
#endif
#ifdef ENOTEMPTY
    [ENOTEMPTY] = "ENOTEMPTY",
#endif
#ifdef ELOOP
    [ELOOP] = "ELOOP",
#endif
#ifdef ENOMSG
    [ENOMSG] = "ENOMSG",
#endif
#ifdef EIDRM
    [EIDRM] = "EIDRM",
#endif
#ifdef EADDRINUSE
    [EADDRINUSE] = "EADDRINUSE",
#endif
#ifdef EADDRNOTAVAIL
    [EADDRNOTAVAIL] = "EADDRNOTAVAIL",
#endif
#ifdef ENETDOWN
    [ENETDOWN] = "ENETDOWN",
#endif
#ifdef ENETUNREACH
    [ENETUNREACH] = "ENETUNREACH",
#endif
#ifdef ENETRESET
    [ENETRESET] = "ENETRESET",
#endif
#ifdef ECONNABORTED
    [ECONNABORTED] = "ECONNABORTED",
#endif
#ifdef ECONNRESET
    [ECONNRESET] = "ECONNRESET",
#endif
#ifdef ENOBUFS
    [ENOBUFS] = "ENOBUFS",
#endif
#ifdef EISCONN
    [EISCONN] = "EISCONN",
#endif
#ifdef ENOTCONN
    [ENOTCONN] = "ENOTCONN",
#endif
#ifdef ETIMEDOUT
    [ETIMEDOUT] = "ETIMEDOUT",
#endif
#ifdef ECONNREFUSED
    [ECONNREFUSED] = "ECONNREFUSED",
#endif
#ifdef EHOSTUNREACH
    [EHOSTUNREACH] = "EHOSTUNREACH",
#endif
#ifdef EALREADY
    [EALREADY] = "EALREADY",
#endif
#ifdef EINPROGRESS
    [EINPROGRESS] = "EINPROGRESS",
#endif
#ifdef ECANCELED
    [ECANCELED] = "ECANCELED",
#endif
};
