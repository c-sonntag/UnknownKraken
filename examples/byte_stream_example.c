#include <unknownecho/init.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_writer.h>

int main() {
    ue_byte_stream *x, *y, *z;

    /* Initialize library */
    ue_init();

    /* Allocate streams */
    x = ue_byte_stream_create();
    y = ue_byte_stream_create();
    z = ue_byte_stream_create();

    /* Create stream x with Hello world content */
    ue_byte_writer_append_string(x, "Hello world !");

    /* Copy x stream to y */
    ue_byte_writer_append_stream(y, x);

    /* Set the virtual cursor of y to the begining */
    ue_byte_stream_set_position(y, 0);

    /* Read next datas as a stream and copy it to z */
    ue_byte_read_next_stream(y, z);

    /**
     * Print all streams in hexadecimals format.
     * It's excepted that x is equal to z. y is a little bigger
     * because it contains the size of x.
     */
    ue_byte_stream_print_hex(x, stdout);
    ue_byte_stream_print_hex(y, stdout);
    ue_byte_stream_print_hex(z, stdout);

    /* Clean-up streams */
    ue_byte_stream_destroy(x);
    ue_byte_stream_destroy(y);
    ue_byte_stream_destroy(z);

    /* Clean-up library */
    ue_uninit();

    return 0;
}
