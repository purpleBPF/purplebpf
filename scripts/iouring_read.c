/* io_uring 으로만 파일을 열고 읽는다. sys_openat / sys_read 를 한 번도 안 부른다.
 * baseline(시스템콜 진입점) 정책이 놓치고 treatment(커널 내부 함수) 정책이 잡는지
 * 확인하는 대조군 실행기.
 *
 * build: gcc -O2 -o iouring_read iouring_read.c -luring
 * usage: ./iouring_read <path>
 */
#include <fcntl.h>
#include <liburing.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DIE(msg, v) do { fprintf(stderr, "%s: %s\n", msg, strerror(-(v))); return 1; } while (0)

static int wait_res(struct io_uring *ring)
{
    struct io_uring_cqe *cqe;
    int r = io_uring_wait_cqe(ring, &cqe);
    if (r < 0) return r;
    r = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return r;
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <path> [--async]\n", argv[0]); return 2; }

    /* --async 는 IOSQE_ASYNC 로 io_wq 커널 워커(iou-wrk-*) 오프로드를 강제한다.
     * 이벤트가 링 소유 프로세스로 귀속되는지 워커로 새는지 가르는 스위치. */
    int force_async = (argc > 2 && strcmp(argv[2], "--async") == 0);

    struct io_uring ring;
    int r = io_uring_queue_init(8, &ring, 0);
    if (r < 0) DIE("queue_init", r);

    /* IORING_OP_OPENAT — sys_openat 진입점을 거치지 않는다 */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_openat(sqe, AT_FDCWD, argv[1], O_RDONLY, 0);
    if (force_async) io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);
    io_uring_submit(&ring);
    int fd = wait_res(&ring);
    if (fd < 0) DIE("openat", fd);

    /* IORING_OP_READ — sys_read 진입점을 거치지 않는다 */
    char buf[4096];
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_read(sqe, fd, buf, sizeof(buf), 0);
    if (force_async) io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);
    io_uring_submit(&ring);
    int n = wait_res(&ring);
    if (n < 0) DIE("read", n);

    printf("io_uring read %d bytes from %s (async=%d)\n", n, argv[1], force_async);
    io_uring_queue_exit(&ring);
    close(fd);
    return 0;
}
