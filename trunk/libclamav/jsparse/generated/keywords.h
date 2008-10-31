/* ANSI-C code produced by gperf version 3.0.3 */
/* Command-line: gperf -E -t -L ANSI-C -C -F ', TOK_ERROR' -c jsparse-keywords.gperf  */
/* Computed positions: -k'1-2' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gnu-gperf@gnu.org>."
#endif

struct keyword { const char *name; int val; };
/* maximum key range = 100, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (const char *str, unsigned int len)
{
  static const unsigned char asso_values[] =
    {
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103,  30,   5,   0,
        5,   0,  10,  50,  35,   5, 103, 103,  25,  55,
        0,  20,  35, 103,   0,  40,  15,   5,  45,  55,
       45,  50, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103, 103, 103, 103, 103,
      103, 103, 103, 103, 103, 103
    };
  return len + asso_values[(unsigned char)str[1]] + asso_values[(unsigned char)str[0]];
}

#ifdef __GNUC__
__inline
#ifdef __GNUC_STDC_INLINE__
__attribute__ ((__gnu_inline__))
#endif
#endif
static const struct keyword *
in_word_set (const char *str, unsigned int len)
{
  enum
    {
      TOTAL_KEYWORDS = 59,
      MIN_WORD_LENGTH = 2,
      MAX_WORD_LENGTH = 12,
      MIN_HASH_VALUE = 3,
      MAX_HASH_VALUE = 102
    };

  static const struct keyword wordlist[] =
    {
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"new", TOK_NEW},
      {"enum", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR},
      {"return", TOK_RETURN},
      {"in", TOK_IN},
      {"int", TOK_FUTURE_RESERVED_WORD},
      {"null", TOK_NULL},
      {"break", TOK_BREAK},
      {"delete", TOK_DELETE},
      {"default", TOK_DEFAULT},
      {"debugger", TOK_FUTURE_RESERVED_WORD},
      {"interface", TOK_FUTURE_RESERVED_WORD},
      {"instanceof", TOK_INSTANCEOF},
      {"", TOK_ERROR},
      {"if", TOK_IF},
      {"try", TOK_TRY},
      {"true", TOK_TRUE},
      {"final", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR},
      {"finally", TOK_FINALLY},
      {"function", TOK_FUNCTION},
      {"transient", TOK_FUTURE_RESERVED_WORD},
      {"const", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR},
      {"do", TOK_DO},
      {"continue", TOK_CONTINUE},
      {"else", TOK_ELSE},
      {"class", TOK_FUTURE_RESERVED_WORD},
      {"double", TOK_FUTURE_RESERVED_WORD},
      {"boolean", TOK_FUTURE_RESERVED_WORD},
      {"for", TOK_FOR},
      {"case", TOK_CASE},
      {"catch", TOK_CATCH},
      {"native", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {"char", TOK_FUTURE_RESERVED_WORD},
      {"float", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR},
      {"private", TOK_FUTURE_RESERVED_WORD},
      {"abstract", TOK_FUTURE_RESERVED_WORD},
      {"protected", TOK_FUTURE_RESERVED_WORD},
      {"false", TOK_FALSE},
      {"public", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {"long", TOK_FUTURE_RESERVED_WORD},
      {"super", TOK_FUTURE_RESERVED_WORD},
      {"export", TOK_FUTURE_RESERVED_WORD},
      {"extends", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR},
      {"this", TOK_THIS},
      {"throw", TOK_THROW},
      {"throws", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {"byte", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR},
      {"static", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {"with", TOK_WITH},
      {"", TOK_ERROR},
      {"import", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {"void", TOK_VOID},
      {"implements", TOK_FUTURE_RESERVED_WORD},
      {"typeof", TOK_TYPEOF},
      {"package", TOK_FUTURE_RESERVED_WORD},
      {"volatile", TOK_FUTURE_RESERVED_WORD},
      {"goto", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"var", TOK_VAR},
      {"", TOK_ERROR},
      {"short", TOK_FUTURE_RESERVED_WORD},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {"while", TOK_WHILE},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {"switch", TOK_SWITCH},
      {"synchronized", TOK_FUTURE_RESERVED_WORD}
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          const char *s = wordlist[key].name;

          if (*str == *s && !strncmp (str + 1, s + 1, len - 1) && s[len] == '\0')
            return &wordlist[key];
        }
    }
  return 0;
}
