#include <unknownecho/protocol/api/relay/relay_point.h>
#include <unknownecho/alloc.h>
#include <unknownecho/string/string_utility.h>

#include <stdarg.h>

ue_relay_point *ue_relay_point_create(const char *current_host, const char *next_host, const char *communication_type) {
    ue_relay_point *point;

    ue_safe_alloc(point, ue_relay_point, 1);
    point->current_host = ue_string_create_from(current_host);
    point->next_host = ue_string_create_from(next_host);
    point->communication_type = ue_string_create_from(communication_type);

    return point;
}

ue_relay_point **ue_relay_points_create(const char *communication_type, int *point_number, int host_number, ...) {
    ue_relay_point **points;
    va_list ap;
    int i;
    const char *host;

    ue_safe_alloc(points, ue_relay_point *, host_number - 1);
    va_start(ap, host_number);

    for (i = 0; i < host_number; i++) {
        host = va_arg(ap, const char *);
        points[i] = ue_relay_point_create(host, )
    }

    va_end(ap);

    return points;
}

void ue_relay_point_destroy(ue_relay_point *point) {
    if (point) {
        ue_safe_free(point->current_host);
        ue_safe_free(point->next_host);
        ue_safe_free(point->communication_type);
        ue_safe_free(point);
    }
}
