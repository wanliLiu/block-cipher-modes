/*
 * Block Cipher Modes of Operation
 * @author Dani Huertas
 * @email huertas.dani@gmail.com
 *
 */

#include <stdarg.h>
#include <sys/time.h>
#include "main.h"
#include "block-cipher.h"

#include "null.h"
#include "aes.h"
#include "ecb.h"
#include "cbc.h"
#include "pcbc.h"
#include "cfb.h"
#include "ofb.h"

options_t options;

blockcipher_t cipher_list[] = {
  { "null", BLOCK_SIZE, null },
  { "aes",  BLOCK_SIZE, aes  },
  { NULL,   0,          NULL }
};

/*
 * Block Cipher Modes of Operation
 * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
 */
blockcipher_mode_t mode_list[] = {
  // name,  iv,    mode_func
  { "ecb",  FALSE, ecb  },
  { "cbc",  TRUE,  cbc  },
  { "pcbc", TRUE,  pcbc },
  { "cfb",  TRUE,  cfb  },
  { "ofb",  TRUE,  ofb  },
  { NULL,   FALSE, NULL }
};

//------------------------------------------------------------------------------
void usage(char *str) {

  fprintf(stdout, "Usage: %s [options]\n", str);
  fprintf(stdout, "Options:\n");
  fprintf(stdout, 
    "\t-c block-cipher : cipher algorithm (default: null)\n"
    "\t-d              : decrypt\n"
    "\t-e              : encrypt\n"
    "\t-i iv           : initialization vector\n"
    "\t-k key          : private key\n"
    "\t-m mode         : mode of operation (default: ecb)\n"
    "\t-r file         : input file to encrypt/decrypt\n"
    "\t-w file         : output file\n"
    "\t-h              : this help\n\n");
}

void finalize() {

}

//------------------------------------------------------------------------------
void set_iv(uint8_t *iv, size_t block_size) {

  srand(time(0));

  uint8_t randval;
  FILE *fd = fopen("/dev/random", "r");

  uint8_t i = 0;
  for ( ; i < block_size; i++) {

    if(fread(&iv[i], sizeof(randval), 1, fd) == 0) {
      fprintf(stderr, "Read 0 bytes from /dev/random\n");
    }
  }

  fclose(fd);
}

//------------------------------------------------------------------------------
int8_t hex_to_bin(char *str, uint8_t *buff, size_t *buff_size) {

  size_t str_length = strlen(str);

  size_t i = 0;
  for ( ; i < str_length && i < BUFFER_SIZE; i++) {

    if ('0' <= str[i] && str[i] <= '9') {
      buff[i/2] |= ((uint8_t )(str[i] - '0')) << (i % 2 == 0 ? 4 : 0);
    } else if ('A' <= str[i] && str[i] <= 'F') {
      buff[i/2] |= (10 + (uint8_t )(str[i] - 'A')) << (i % 2 == 0 ? 4 : 0);
    } else if ('a' <= str[i] && str[i] <= 'f') {
      buff[i/2] |= (10 + (uint8_t )(str[i] - 'a')) << (i % 2 == 0 ? 4 : 0);
    } else {
      return -1;
    }
  }

  *buff_size = i/2;

  return 0;
}

//------------------------------------------------------------------------------
void get_options(int argc, char *argv[]) {

  int o;

  while ((o = getopt(argc, argv, "hc:dei:k:m:r:w:v")) != -1) {

    switch (o) {

      case 'c':
        options.cipher = optarg;
        break;

      case 'd':
        options.direction = DECRYPT;
        break;

      case 'e':
        options.direction = ENCRYPT;
        break;

      case 'i':
        options.iv = optarg;
        break;

      case 'k':
        options.key = optarg;
        break;

      case 'm':
        options.mode = optarg;
        break;

      case 'r':
        options.read_file = optarg;
        break;

      case 'w':
        options.write_file = optarg;
        break;

      case '?':
        if (optopt == 'c') {
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        } else if (isprint (optopt)) {
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        } else {
          fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
        }
        break;

      case 'h':
      default:
        usage(argv[0]);
        exit(0);
        break;
    }
  }
}


static void err_quit(const char *fmt, ...) {
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  strcat(buf, "\n");
  fputs(buf, stderr);
  fflush(stderr);
  va_end(ap);

  exit(1);
}


void syntax(const char* program_name) {
  err_quit("usage: %s <cfb|ofb>"
      " <要加密的十六进制字符串>"
      " <Key>"
      " <IV>", program_name);
}

static void read_hex(const char *in, uint8_t* v, size_t size, const char* param_name) {
  if (strlen(in) != size << 1) {
    err_quit("Invalid param %s (got %d, expected %d)",
        param_name, strlen(in), size << 1);
  }
  for (size_t i = 0; i < size; i++) {
    sscanf(in + i * 2, "%2hhx", v + i);
  }
}


uint64_t get_cur_time_ms() {
  // 获得当前时间us为单位
  struct timeval tv;
  struct timezone tz;
  gettimeofday(&tv, &tz);
  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}
uint64_t get_cur_time_us() {
  struct timeval tv;
  struct timezone tz;
  gettimeofday(&tv, &tz);
  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

#define getTime get_cur_time_us


int main(int argc, char *argv[]) {

  char *mode = "";
  if (argc != 5) {
      syntax(argv[0]);
  } else if (strcmp(argv[1], "cfb") == 0) {
      mode = "cfb";
  } else if (strcmp(argv[1], "ofb") == 0) {
      mode = "ofb";
  } else {
      syntax(argv[0]);
  }

  size_t inputLen = strlen(argv[2]);
  if (inputLen > 0 && inputLen % 2 != 0) {
      err_quit("输入要加密的十六进制字符串的个数必须是偶数，当前输入的字符个数是：%d", inputLen);
  }

  if (strlen(argv[3]) % 32 != 0) {
      err_quit("输入的key必须是16个十六进制数据");
  }

  if (strlen(argv[4]) % 32 != 0) {
      err_quit("输入的IV必须是16个十六进制数据");
  }

  uint8_t *key = NULL;
  int inputByte = inputLen / 2;
  int inputBlock = inputByte;
  if (inputByte % 16 != 0) {
    inputBlock = (inputByte / 16 + 1) * 16;
  }
  uint8_t plain[inputBlock], key_buffer[16], iv_or_nonce[16], output[inputBlock];

  read_hex(argv[2], plain, inputByte, "plain");
  read_hex(argv[3], key_buffer, 16, "key");
  key = aes_init(16);
  aes_key_expansion(key_buffer, key);
  read_hex(argv[4], iv_or_nonce, 16, "iv-or-nonce");

  printf("--> 输入的十六进制字符串长度：%d 十六进制个数 %d\n", inputLen, inputByte);
  printf("--> 开始%s加密:\n", argv[1]);
  for(int index = 0; index < inputByte; index++)
      printf("%.2x", plain[index]);

  blockcipher_mode_t *bc_mode = bc_get_mode(mode, mode_list);
  blockcipher_t *bc = bc_get_blockcipher("aes", cipher_list);

  if (!bc_mode) {
    printf(2, "Mode not found\n");
    exit(1);
  }
 
  if (!bc) {
    fprintf(2, "Cipher not found\n");
    exit(1);
  }

  uint8_t *in_buffer = plain;
  uint8_t *end_buffer = plain + inputByte;
  uint8_t *out_buffer = output;
  size_t read_size = 0;
  size_t write_size = 0;
  uint64_t timeStart = getTime();
  printf("\n--> 中间值 start %lldus", timeStart);
  for (;;) {
    if (in_buffer + bc->block_size <= end_buffer)
        read_size = bc->block_size;
    else if (in_buffer + bc->block_size > end_buffer)
        read_size = end_buffer - in_buffer;
    // printf("\n----> read_size = %d\n", read_size);
    uint8_t last_block = in_buffer + bc->block_size == end_buffer || read_size < bc->block_size ? TRUE : FALSE;
    // if (last_block && read_size < bc->block_size) {
    //   bc_add_padding(in_buffer, bc->block_size, read_size);
    //   // printf("\n----> bc_add_padding  \n");
    // }
    // Mode and cipher operations
    write_size = bc_mode->func(bc->func, ENCRYPT,
      in_buffer, out_buffer, iv_or_nonce, key, 16,
      bc->block_size, read_size, last_block);
    if (last_block) {
      break;
    }

    in_buffer += bc->block_size;
    out_buffer += write_size;
  }

  uint64_t timeEnd = getTime();
  printf("\n--> 中间值 end %lldus cost %lldus", timeEnd , timeEnd - timeStart);
  printf("\n--> 加密后的密文：\n");
  for(int index = 0; index < inputByte; index++)
    printf("%.2x", output[index]);
  printf("\n\n\n");

  printf("--> 开始%s解密：\n", argv[1]);
  for(int index = 0; index < inputByte; index++)
      printf("%.2x", output[index]);
  printf("\n");

  in_buffer = output;
  end_buffer = output + sizeof(output);
  out_buffer = plain;
  read_size = 0;
  write_size = 0;
  timeStart = getTime();
  printf("\n--> 中间值 start %lldus", timeStart);
  for (;;) {

    read_size = bc->block_size;
    uint8_t last_block = in_buffer + bc->block_size == end_buffer ? TRUE : FALSE;

    // Mode and cipher operations
    write_size = bc_mode->func(bc->func, DECRYPT,
      in_buffer, out_buffer, iv_or_nonce, key, 16,
      bc->block_size, read_size, last_block);
    if (last_block) {
      break;
    }

    in_buffer += bc->block_size;
    out_buffer += write_size;

    // if (last_block && options.direction == DECRYPT) {
    //   write_size = bc_remove_padding(out_buffer, bc->block_size, read_size);
    //   break;
    // }
  }

  timeEnd = getTime();
  printf("\n--> 中间值 end %lldus cost %lldus", timeEnd , timeEnd - timeStart);
  printf("\n--> 解密后的明文：\n");
  for(int index = 0; index < inputByte; index++)
      printf("%.2x", plain[index]);
  printf("\n\n\n");

  free(key);
  key = NULL;
}

//------------------------------------------------------------------------------
int old_main(int argc, char *argv[]) {

  size_t read_size = 0;
  size_t write_size = 0;
  size_t total_read = 0;

  size_t key_size = 0;
  size_t iv_size = 0;

  uint8_t key_buffer[MAX_KEY_SIZE];
  uint8_t iv[MAX_IV_SIZE];

  uint8_t in_buffer[BUFFER_SIZE];
  uint8_t out_buffer[BUFFER_SIZE];

  uint8_t *key = NULL;

  FILE *read_fd = NULL, 
       *write_fd = NULL;

  memset(key_buffer, 0, MAX_KEY_SIZE);
  memset(iv, 0, MAX_IV_SIZE);

  memset(in_buffer, 0, BUFFER_SIZE);
  memset(out_buffer, 0, BUFFER_SIZE);

  if (argc < 2) {
    usage(argv[0]);
    exit(0);
  }

  options.cipher = "null";
  options.mode = "ecb";
  options.key = NULL;
  options.iv = NULL;
  options.read_file = NULL;
  options.write_file = NULL;
  options.verbose = 0;

  get_options(argc, argv);

  if (options.key != NULL) {
    if (hex_to_bin(options.key, key_buffer, &key_size) != 0) {
      fprintf(stderr, "Invalid key format\n");
      exit(1);
    }
  } else {
    fprintf(stderr, "Missing key\n");
    exit(1);
  }

  if (options.iv != NULL) {
    if (hex_to_bin(options.iv, iv, &iv_size) != 0) {
      fprintf(stderr, "Invalid IV format\n");
      exit(1);
    }
  }

  if (options.read_file != NULL) {
    if ((read_fd = fopen(options.read_file, "rb")) == NULL) {
      fprintf(stderr, "Error opening read file: %s\n", options.read_file);
      exit(1);
    }
  } else {
    fprintf(stderr, "Missing read file\n");
    exit(1);
  }

  if (options.write_file != NULL) {
    if ((write_fd = fopen(options.write_file, "wb")) == NULL) {
      fprintf(stderr, "Error opening write file: %s\n", options.write_file);
      exit(1);
    }
  } else {
    fprintf(stderr, "Missing write file\n");
    exit(1);
  }

  blockcipher_mode_t *bc_mode = bc_get_mode(options.mode, mode_list);

  blockcipher_t *bc = bc_get_blockcipher(options.cipher, cipher_list);

  if ( ! bc_mode) {
    fprintf(stderr, "Mode not found: %s\n", options.mode);
    exit(1);
  }
 
  if ( ! bc) {
    fprintf(stderr, "Cipher not found: %s\n", options.cipher);
    exit(1);
  }

  if (bc->func == aes) {
    key = aes_init(key_size);
    aes_key_expansion(key_buffer, key);
  } else {
    key = key_buffer;
  }

  // Get file size
  fseek(read_fd, 0L, SEEK_END);
  size_t file_size = ftell(read_fd);

  if (options.direction == DECRYPT) {

    if ((bc_mode->iv && file_size < 2*bc->block_size) || 
        ( ! bc_mode->iv && file_size < bc->block_size)) {

      fprintf(stderr, "Invalid file size: %lu\n", file_size);
      exit(1);
    }
  }

  rewind(read_fd);

  // IV part
  if (bc_mode->iv) {

    switch (options.direction) {

      case ENCRYPT:

        if (options.iv == NULL) {
          set_iv(iv, bc->block_size);
        }

        // Prepend file with IV
        fwrite(iv, 1, bc->block_size, write_fd);
        break;

      case DECRYPT:

        // Read prepended IV
        read_size = fread(iv, 1, bc->block_size, read_fd);
        total_read += read_size;
        break;
    }
  }

  for (;;) {

    read_size = fread(in_buffer, 1, bc->block_size, read_fd);

    total_read += read_size;

    uint8_t last_block = total_read >= file_size ? TRUE : FALSE;

    if (last_block && options.direction == ENCRYPT && read_size < bc->block_size) {
      bc_add_padding(in_buffer, bc->block_size, read_size);
    }

    // Mode and cipher operations
    write_size = bc_mode->func(bc->func, options.direction,
      in_buffer, out_buffer, iv, key, key_size,
      bc->block_size, read_size, FALSE);

    if (last_block && options.direction == ENCRYPT && read_size == bc->block_size) {

      fwrite(out_buffer, 1, write_size, write_fd);

      memset(in_buffer, 0, BUFFER_SIZE);
      bc_add_padding(in_buffer, bc->block_size, read_size);

      write_size = bc_mode->func(bc->func, options.direction,
        in_buffer, out_buffer, iv, key, key_size,
        bc->block_size, read_size, TRUE);

      fwrite(out_buffer, 1, write_size, write_fd);
      break;

    } else if (last_block && options.direction == ENCRYPT && read_size < bc->block_size) {

      fwrite(out_buffer, 1, write_size, write_fd);
      break;
    }

    if (last_block && options.direction == DECRYPT) {

      write_size = bc_remove_padding(out_buffer, bc->block_size, read_size);
      fwrite(out_buffer, 1, write_size, write_fd);
      break;
    }

    fwrite(out_buffer, 1, write_size, write_fd);
  }

  // Clean up
  if (read_fd != NULL) fclose(read_fd);

  if (write_fd != NULL) fclose(write_fd);

  memset(key, 0, key_size);
  memset(key_buffer, 0, MAX_KEY_SIZE);

  if (bc->func == aes) {
    free(key);
    key = NULL;
  }

  return 0;
}
