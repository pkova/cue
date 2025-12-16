typedef unsigned char      u8;
typedef int                b32;
typedef int                i32;
typedef long long          i64;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef char               byte;

#if defined(_WIN64) || defined(__x86_64__) || defined(__aarch64__)
    typedef unsigned long long uptr;
    typedef long long          size;
    typedef unsigned long long usize;
#else
    typedef unsigned int       uptr;
    typedef int                size;
    typedef unsigned int       usize;
#endif

#ifdef DEBUG
#  if __GNUC__
#    define assert(c) if (!(c)) __builtin_trap()
#  elif _MSC_VER
#    define assert(c) if (!(c)) __debugbreak()
#  else
#    define assert(c) if (!(c)) *(volatile i32 *)0 = 0
#  endif
#else
#  define assert(c)
#endif

#define sizeof(x)    (size)sizeof(x)
#define alignof(x)   (size)_Alignof(x)
#define countof(a)   (sizeof(a)/sizeof(*(a)))
#define lengthof(s)  (countof(s) - 1)
#define new(a, t, n) (t *)alloc(a, sizeof(t), alignof(t), n)
#define pop(a, t)    (t *)arenapop(a, sizeof(t))
#define peek(a, t)    (t *)arenapeek(a, sizeof(t))

#define S(s) (s8){(u8 *)(s), lengthof(s)}

#define u3_none (noun*)0xffffffffffffffff
#define ur_min(a, b)   ( ((a) < (b)) ? (a) : (b) )
#define ur_tz32 __builtin_ctz
#define ur_tz8  ur_tz32
#define ur_mask_3(a)   (a & 0x7)

typedef struct {
  byte *dat;
  byte *beg;
  byte *end;
  byte *com;
} arena;

typedef enum {
  jam_atom = 0,
  jam_cell = 1,
  jam_back = 2
} cuetag;

typedef struct {
  u8 *buf;
  i32 len;
  i32 cap;
  i32 fd;
  b32 err;
} bufout;

typedef struct {
  u8  *buf;
  size len;
} s8;

typedef struct noun noun;
struct noun {
  union {
    struct {
      u64 val;
      u64 len;
    };
    struct {
      noun *head;
      noun *tail;
    };
  };
};

typedef struct map map;
struct map {
  map  *child[4];
  u64  key;
  noun* val;
};

typedef enum {
  ur_cue_good = 0,    //  successful read
  ur_cue_back = 1,    //  missing backreference
  ur_cue_gone = 2,    //  read off the end of the stream
  ur_cue_meme = 3     //  exceeded memory representation
} ur_cue_res_e;

typedef struct reader {
  u64 left;
  u64 bits;
  u8  off;
  u8  *bytes;
} reader;

typedef struct cueframe {
  noun *ref;
  u64  bits;
} cueframe;

void osfail(void);
b32  oswrite(i32, u8 *, i32);
i32  osread(size, u8 *, i32);
void *osreserve(size);
i32  oscommit(void *, size);
void *oscopy(void *, void *, size);

b32 iscell(noun* n) {
  return (b32)((n->val & (1ULL << 63)) > 0);
}

void oom(void) {
  static const u8 msg[] = "out of memory\n";
  oswrite(2, (u8 *)msg, lengthof(msg));
  osfail();
}

__attribute((malloc))
byte *alloc(arena *a, size objsize, size align, size count) {
  size avail = a->com - a->beg;
  size padding = -(uptr)a->beg & (align - 1);
  if (count > (avail - padding)/objsize) {
    if (-1 == oscommit(a->com, (1ull<<24))) {
      oom();
    }
    a->com += (1ull<<24);
  }
  size total = count * objsize;
  byte *p = a->beg + padding;
  a->beg += padding + total;
  // for (size i = 0; i < total; i++) {
    // p[i] = 0;
  // }
  return p;
}



void *arenapeek(arena *a, size objsize) {
  byte* beg = a->beg - objsize;
  return (void *)beg;
}

void *arenapop(arena *a, size objsize) {
  a->beg -= objsize;
  byte* beg = a->beg - objsize;
  return (void *)beg;
}

noun* head(noun *n) {
  return (noun*)((u64)n->head & ~(1ULL << 63));
}

noun* tail(noun *n) {
  return n->tail;
}

void flush(bufout *b) {
  b->err |= b->fd < 0;
  if (!b->err && b->len) {
    b->err |= !oswrite(b->fd, b->buf, b->len);
    b->len = 0;
  }
}

void append(bufout *b, s8 src) {
  u8 *end = src.buf + src.len;
  while (!b->err && src.buf<end) {
    size left = end - src.buf;
    size avail = b->cap - b->len;
    size amount = avail<left ? avail : left;

    for (size i = 0; i < amount; i++) {
      b->buf[b->len+i] = src.buf[i];
    }
    b->len += amount;
    src.buf += amount;

    if (amount < left) {
      flush(b);
    }
  }
}

void appendhex(bufout *b, u8 c) {
  s8 digits = S("0123456789abcdef");
  u8 out[2];
  out[0] = digits.buf[(c&0xf0)>>4];
  out[1] = digits.buf[c&0x0f];
  s8 s = {.buf = out, .len = 2};
  append(b, s);
}

void appendhexbuf(bufout *b, u8* d, size len) {
  append(b, S("0x"));
  size j = len % 2;
  for (size i = len-1; i >= 0; i--, j++) {
    if (j % 2 == 0) {
      append(b, S("."));
    }
    appendhex(b, d[i]);
  }
}

void appendnoun(bufout *b, b32 hed, noun *n) {
  if (iscell(n)) {
    if (hed) {
      append(b, S("["));
    }

    appendnoun(b, 1, head(n));
    append(b, S(" "));
    appendnoun(b, 0, tail(n));
    if (hed) {
      append(b, S("]"));
    }
  } else {
    if (n->len > 8) {
      appendhexbuf(b, (u8*)n->val, n->len);
    } else if (n->len == 0) {
      append(b, S("0x0"));
    } else {
      appendhexbuf(b, (u8*)&n->val, n->len);
    }
  }
}

u64 hash64(u64 x) {
  x ^= x >> 30;
  x *= 0xbf58476d1ce4e5b9U;
  x ^= x >> 27;
  x *= 0x94d049bb133111ebU;
  x ^= x >> 31;
  return x;
}


b32 get(map **m, u64 key, noun **out) {
  for (u64 h = hash64(key); *m; h <<= 2) {
    if (key == (*m)->key) {
      *out = (*m)->val;
      return 1;
    }
    m = &(*m)->child[h>>62];
  }
  return 0;
}

b32 upsert(map **m, u64 key, noun* val, arena *a) {
  for (u64 h = hash64(key); *m; h <<= 2) {
    if (key == (*m)->key) {
      return 1;
    }
    m = &(*m)->child[h>>62];
  }
  *m = new(a, map, 1);
  (*m)->key = key;
  (*m)->val = val;
  return 0;
}

ur_cue_res_e _bsr_log_meme(reader *bsr) {
  bsr->bits += 256;
  bsr->bytes += 32;
  bsr->left  -= 32;
  return ur_cue_meme;
}

ur_cue_res_e _bsr_set_gone(reader *bsr, u8 bits) {
  bsr->bits += bits;
  bsr->bytes = 0;
  bsr->left  = 0;
  bsr->off   = 0;
  return ur_cue_gone;
}

ur_cue_res_e ur_bsr_log(reader *bsr, u8 *out) {
  u64 left = bsr->left;

  if ( !left ) {
    return ur_cue_gone;
  }
  else {
    u8 off = bsr->off;
    u8 *b = bsr->bytes;
    u8 byt = b[0] >> off;
    u8 skip = 0;

    while ( !byt ) {
      if ( 32 == skip ) {
        return _bsr_log_meme(bsr);
      }

      byt = b[++skip];

      if ( skip == left ) {
        return _bsr_set_gone(bsr, (u8)(skip << 3) - off);
      }
    }

    {
      u32 zeros = ur_tz8(byt) + (skip ? ((skip << 3) - off) : 0);

      if ( 255 < zeros ) {
        return _bsr_log_meme(bsr);
      }
      else {
        u32 bits = off + 1 + zeros;
        u8 bytes = (u8)(bits >> 3);

        left -= bytes;

        bsr->bytes = left ? (b + bytes) : 0;
        bsr->bits += 1 + zeros;
        bsr->left  = left;
        bsr->off   = ur_mask_3(bits);

        *out = (u8)zeros;
        return ur_cue_good;
      }
    }
  }
}


u64 ur_bsr64_any(reader *bsr, u8 len)
{
  u64 left = bsr->left;

  len = ur_min(64, len);

  bsr->bits += len;

  if ( !left ) {
    return 0;
  }
  else {
    u8  off = bsr->off;
    u8 rest = 8 - off;
    u64   m = bsr->bytes[0] >> off;

    if ( len < rest ) {
      bsr->off = off + len;
      return m & ((1 << len) - 1);
    }
    else {
      u8  *b;
      u8  mask, len_byt;
      u64 l;

      len -= rest;
      left--;
      b = ++bsr->bytes;

      len_byt = len >> 3;

      if ( len_byt >= left ) {
        len_byt    = (u8)left;
        bsr->off   = off = 0;
        bsr->left  = 0;
        bsr->bytes = 0;
      }
      else {
        bsr->off    = off = ur_mask_3(len);
        bsr->left   = left - len_byt;
        bsr->bytes += len_byt;
      }

      mask = (u8)((1 << off) - 1);

      switch ( len_byt ) {
      case 8: {
        l = (u64)b[0]
          ^ (u64)b[1] << 8
          ^ (u64)b[2] << 16
          ^ (u64)b[3] << 24
          ^ (u64)b[4] << 32
          ^ (u64)b[5] << 40
          ^ (u64)b[6] << 48
          ^ (u64)b[7] << 56;
      } break;

      case 7: {
        l = (u64)b[0]
          ^ (u64)b[1] << 8
          ^ (u64)b[2] << 16
          ^ (u64)b[3] << 24
          ^ (u64)b[4] << 32
          ^ (u64)b[5] << 40
          ^ (u64)b[6] << 48;

        if ( mask ) {
          l ^= (u64)(b[7] & mask) << 56;
        }
      } break;

      case 6: {
        l = (u64)b[0]
          ^ (u64)b[1] << 8
          ^ (u64)b[2] << 16
          ^ (u64)b[3] << 24
          ^ (u64)b[4] << 32
          ^ (u64)b[5] << 40;

        if ( mask ) {
          l ^= (u64)(b[6] & mask) << 48;
        }
      } break;

      case 5: {
        l = (u64)b[0]
          ^ (u64)b[1] << 8
          ^ (u64)b[2] << 16
          ^ (u64)b[3] << 24
          ^ (u64)b[4] << 32;

        if ( mask ) {
          l ^= (u64)(b[5] & mask) << 40;
        }
      } break;

      case 4: {
        l = (u64)b[0]
          ^ (u64)b[1] << 8
          ^ (u64)b[2] << 16
          ^ (u64)b[3] << 24;

        if ( mask ) {
          l ^= (u64)(b[4] & mask) << 32;
        }
      } break;

      case 3: {
        l = (u64)b[0]
          ^ (u64)b[1] << 8
          ^ (u64)b[2] << 16;

        if ( mask ) {
          l ^= (u64)(b[3] & mask) << 24;
        }
      } break;

      case 2: {
        l = (u64)b[0]
          ^ (u64)b[1] << 8;

        if ( mask ) {
          l ^= (u64)(b[2] & mask) << 16;
        }
      } break;

      case 1: {
        l = (u64)b[0];

        if ( mask ) {
          l ^= (u64)(b[1] & mask) << 8;
        }
      } break;

      case 0: {
        l = ( mask ) ? (u64)(b[0] & mask) : 0;
      } break;
      }

      return m ^ (l << rest);
    }
  }
}

ur_cue_res_e ur_bsr_rub_len(reader *bsr, u64 *out)
{
  ur_cue_res_e res;
  u8      len;

  if ( ur_cue_good != (res = ur_bsr_log(bsr, &len)) ) {
    return res;
  }
  else if ( 64 <= len ) {
    return ur_cue_meme;
  }

  switch ( len ) {
  case 0: {
    *out = 0;
  } break;

  case 1: {
    *out = 1;
  } break;

  default: {
    len--;
    *out = ur_bsr64_any(bsr, len) ^ (1ULL << len);
  } break;
  }

  return ur_cue_good;
}

void ur_bsr_bytes_any(reader *bsr, u64 len, u8 *out) {
  u64 left = bsr->left;

  bsr->bits += len;

  if ( !left ) {
    return;
  }
  else {
    u8  *b = bsr->bytes;
    u8  off = bsr->off;
    u64 len_byt = len >> 3;
    u8  len_bit = ur_mask_3(len);
    u64 need = len_byt + !!len_bit;

    if ( !off ) {
      if ( need > left ) {
        oscopy(out, b, left);
        left = 0;
        bsr->bytes = 0;
      }
      else {
        oscopy(out, b, len_byt);
        off = len_bit;

        if ( off ) {
          out[len_byt] = b[len_byt] & ((1 << off) - 1);
        }

        left -= len_byt;
        bsr->bytes = ( left ) ? b + len_byt : 0;
      }
    }
    //  the most-significant bits from a byte in the stream
    //  become the least-significant bits of an output byte, and vice-versa
    //
    else {
      u8  rest = 8 - off;
      u64 last = left - 1;
      u64  max = ur_min(last, len_byt);
      u8  m, l;

      //  loop over all the bytes we need (or all that remain)
      //
      {
        u64 i;

        for ( i = 0; i < max; i++ ) {
          out[i] = (u8)((b[i] >> off) ^ (b[i + 1] << rest));
        }

        b += max;
        m = *b >> off;
      }

      //  we're reading into or beyond the last byte [bsr]
      //
      //    [m] holds all the remaining bits in [bsr],
      //    but we might not need all of it
      //
      if ( need >= left ) {
        u8 bits = (u8)(len - (last << 3));

        if ( bits < rest ) {
          out[max] = m & ((1 << len_bit) - 1);
          bsr->bytes = b;
          left = 1;
          off += len_bit;
        }
        else {
          out[max] = m;
          bsr->bytes = 0;
          left = 0;
          off  = 0;
        }
      }
      //  we need less than a byte, but it might span multiple bytes
      //
      else {
        u8 bits = off + len_bit;
        u8 step = !!(bits >> 3);

        bsr->bytes = b + step;
        left -= len_byt + step;
        off   = ur_mask_3(bits);

        if ( len_bit ) {
          if ( len_bit <= rest ) {
            out[max] = m & ((1 << len_bit) - 1);
          }
          else {
            l = *++b & ((1 << off) - 1);
            out[max] = (u8)((m ^ (l << rest)) & ((1 << len_bit) - 1));
          }
        }
      }
    }

    bsr->off  = off;
    bsr->left = left;
  }
}

ur_cue_res_e
ur_bsr_tag(reader *bsr, cuetag *out)
{
  u64 left = bsr->left;

  if ( !left ) {
    return ur_cue_gone;
  }
  else {
    u8 *b = bsr->bytes;
    u8 off = bsr->off;
    u8 bit = (b[0] >> off) & 1;
    u8 len = 1;

    if ( 0 == bit ) {
      *out = jam_atom;
    }
    else {
      if ( 7 == off ) {
        if ( 1 == left ) {
          return _bsr_set_gone(bsr, 1);
        }

        bit = b[1] & 1;
      }
      else {
        bit = (b[0] >> (off + 1)) & 1;
      }

      len++;
      *out = ( 0 == bit ) ? jam_cell : jam_back;
    }

    {
      u8 bits = off + len;
      u8 bytes = bits >> 3;

      left -= bytes;

      if ( !left ) {
        bsr->bytes = 0;
        bsr->left  = 0;
        bsr->off   = 0;
      }
      else {
        bsr->bytes += bytes;
        bsr->left   = left;
        bsr->off    = ur_mask_3(bits);
      }

      bsr->bits += len;

      return ur_cue_good;
    }
  }
}

ur_cue_res_e cuenext(arena *stack, arena *scratch, arena *perm, reader *r, map **m, noun **out) {
  while ( 1 ) {
    u64  len, bit = r->bits;
    cuetag tag;
    ur_cue_res_e res_e;

    if ( ur_cue_good != (res_e = ur_bsr_tag(r, &tag)) ) {
      return res_e;
    }

    switch ( tag ) {
    default: assert(0);

    case jam_cell: {
      cueframe *f = new(stack, cueframe, 1);

      f->ref = u3_none;
      f->bits = bit;
      continue;
    }

    case jam_back: {
      if ( ur_cue_good != (res_e = ur_bsr_rub_len(r, &len)) ) {
        return res_e;
      }
      else if ( 62 < len ) {
        return ur_cue_meme;
      }
      else {
        u64 bak_d = ur_bsr64_any(r, (u8)len);
        noun* bak_w;

        if ( !(get(m, bak_d, &bak_w)) ) {
          return ur_cue_back;
        }

        *out = bak_w;
        return ur_cue_good;
      }
    }

    case jam_atom: {
      if ( ur_cue_good != (res_e = ur_bsr_rub_len(r, &len)) ) {
        return res_e;
      }

      if ( 63 >= len ) {
        noun *n = new(perm, noun, 1);
        n->val = ur_bsr64_any(r, (u8)len);
        n->len = (len + 7) / 8;
        *out = n;
      }
      else {
        u64 byt = (len + 7) / 8;

        if (0xffffffffULL < byt) {
          return ur_cue_meme;
        }
        else {
          u8 *buf = new(perm, u8, byt);
          ur_bsr_bytes_any(r, len, buf);

          noun *n = new(perm, noun, 1);
          n->val = (u64)buf;
          n->len = byt;
          *out = n;
        }
      }

      upsert(m, bit, *out, scratch);
      return ur_cue_good;
    }
    }
  }
}


noun* cue(u8 *buf, u64 len, arena *perm, arena *stack, arena *scratch) {
  reader r = {0};
  r.bytes = buf;
  r.left = len;

  cueframe* f;
  map* m = 0;

  noun* n = 0;

  ur_cue_res_e res = cuenext(stack, scratch, perm, &r, &m, &n);

  if ((stack->beg > stack->dat) && (ur_cue_good == res)) {
    f = peek(stack, cueframe);
    do {
      //  f is a head-frame; stash result and read the tail from the stream
      //
      if ( u3_none == f->ref ) {
        f->ref = n;
        res = cuenext(stack, scratch, perm, &r, &m, &n);
        f = peek(stack, cueframe);
      }
      //  f is a tail-frame; pop the stack and continue
      //
      else {
        noun* new = new(perm, noun, 1);
        new->head = (noun*)((u64)f->ref ^ (1ULL << 63));
        new->tail = n;
        n = new;
        upsert(&m, f->bits, n, scratch);
        f = pop(stack, cueframe);
      }
    }
    while ((stack->beg > stack->dat)  && (ur_cue_good == res));
  }
  return n;
}

arena initarena() {
  arena a = {0};
  a.beg = osreserve(1ull<<34);
  oscommit(a.beg, 1ull<<24);
  a.dat = a.beg;
  a.end = a.beg + (1ull<<34);
  a.com = a.beg + (1ull<<24);
  return a;
}

i32 cuemain() {

  arena a = initarena();
  arena scratch = initarena();
  arena stack = initarena();

  size cap = 1<<12;

  bufout stdout[1] = {0};
  stdout->fd = 1;
  stdout->cap = (i32)cap;
  stdout->buf = new(&a, u8, cap);

  size out = 0;
  size len = 0;
  u8 *d = new(&a, u8, 1<<16);
  while ((out = osread(0, d + len, 1<<16)) > 0){
    len += out;
    new(&a, u8, 1<<16);
  }

  if (len > 0) {
    noun* n = cue(d, len, &a, &stack, &scratch);
    appendnoun(stdout, 1, n);
    append(stdout, S("\n"));
    flush(stdout);
  }
  return 0;
}

#ifdef _WIN32
typedef struct {i32 dummy;} *handle;

#define W32(r) __declspec(dllimport) r __stdcall

W32(void *) GetStdHandle(i32);
W32(i32)    ReadFile(handle, u8 *, i32, u32 *, void *);
W32(void)   ExitProcess(i32);
W32(void)   CopyMemory(void *, void *, size);
W32(void *) VirtualAlloc(void *, usize, i32, i32);

void osfail(void){
  ExitProcess(1);
}

i32 osread(size fd, u8 *buf, i32 cap) {
  u32 len;
  ReadFile((handle)fd, buf, cap, &len, 0);
  return len;
}

b32 oswrite(i32 fd, u8 *buf, i32 len) {
  handle stdout = GetStdHandle(-10 - fd);
  u32 dummy;
  return WriteFile(stdout, buf, len, &dummy, 0);
}

void *oscopy(void *dst, void *src, size len) {
  CopyMemory(dst, src, len);
  return dst;
}

void *osreserve(size len) {
  #define MEM_RESERVE 0x2000
  #define PAGE_NOACCESS 0x01

  void *res = VirtualAlloc(0, len, MEM_RESERVE, PAGE_NOACCESS);
  if (res == 0) {
    oom();
  }
  return res;
}

i32 oscommit(void *base, size len) {
  #define MEM_COMMIT 0x1000
  #define PAGE_READWRITE 0x04
  usize res = VirtualAlloc(base, len, MEM_COMMIT, PAGE_READWRITE);
  return res == 0 ? -1 : 0;
}

void mainCRTStartup(void) {
  i32 r = cuemain();
  ExitProcess(r);
}

#else

size write(i32, void *, size);
size read(i32, void *, size);
void _exit(i32) __attribute__((noreturn));
void *mmap(void *, size, i32, i32, i32, size);
i32  mprotect(void *, size, i32);

void osfail(void) {
  _exit(1);
}

i32 osread(size fd, u8 *buf, i32 cap) {
  return (i32)read((i32)fd, buf, cap);
}

b32 oswrite(i32 fd, u8 *buf, i32 len) {
  for (i32 off = 0; off < len;) {
    i32 r = (i32)write(fd, buf+off, len-off);
    if (r < 1) {
      return 0;
    }
    off += r;
  }
  return 1;
}

i32 oscommit(void *base, size len) {
  #define PROT_READ  0x1
  #define PROT_WRITE 0x2
  return mprotect(base, len, PROT_READ|PROT_WRITE);
}

void *oscopy(void *dst, void *src, size len) {
  if (len > 0) {
    return __builtin_memcpy(dst, src, len);
  }
  return dst;
}

void *osreserve(size len) {
  #define PROT_NONE 0
  #define MAP_PRIVATE 0x2
  #ifdef __APPLE__
  #define MAP_ANONYMOUS 0x1000
  #else
  #define MAP_ANONYMOUS 0x20
  #endif

  void *res = mmap(0, len, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (res == (void *)-1) {
    oom();
  }
  return res;
}

int main() {
  return cuemain();
}

#endif
