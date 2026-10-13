/* Distinct diagnostic: the same policy applies only AFTER this native helper starts. */
#include <sandbox.h>

#define main probe_main
#include "probe.c"
#undef main

int main(int argc, char **argv) {
    if (argc == 3) return probe_main(argc, argv);
    if (argc != 5 || strcmp(argv[1], "--apply-profile-after-startup") != 0) return 2;
    if (limits() != 0 || setvbuf(stdout, NULL, _IONBF, 0) != 0) return 2;
    char *error = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int applied = sandbox_init(argv[2], 0, &error);
#pragma clang diagnostic pop
    if (applied != 0) {
        fprintf(stderr, "custom_sandbox_apply_failed errno=%d detail=%.512s\n",
                errno, error != NULL ? error : "unavailable");
        if (error != NULL) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            sandbox_free_error(error);
#pragma clang diagnostic pop
        }
        return 4;
    }
    char *args[] = {argv[0], argv[3], argv[4], NULL};
    return probe_main(3, args);
}
