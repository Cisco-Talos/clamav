/* ANSI-C code produced by gperf version 3.0.3 */
/* Command-line: gperf -E -t -L ANSI-C -C -F ', TOK_ERROR' -c -H op_hash -N in_op_set -W oplist ../../../../trunk/libclamav/jsparse/operators.gperf  */
/* Computed positions: -k'1,$' */

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

struct operator {
	const char *name;
	int val;
};
/* maximum key range = 121, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
op_hash (const char *str, unsigned int len)
{
  static const unsigned char asso_values[] =
    {
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122,  50, 122, 122, 122,  31,  40, 122,
      122, 122,  21,  30, 122,  25, 122,  16, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122,  45, 122,
       10,   5,   0,  35, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122,  60, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122,  20, 122,  15, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
      122, 122, 122, 122, 122, 122
    };
  return len + asso_values[(unsigned char)str[len - 1]] + asso_values[(unsigned char)str[0]];
}

#ifdef __GNUC__
__inline
#ifdef __GNUC_STDC_INLINE__
__attribute__ ((__gnu_inline__))
#endif
#endif
static const struct operator *
in_op_set (const char *str, unsigned int len)
{
  enum
    {
      TOTAL_KEYWORDS = 39,
      MIN_WORD_LENGTH = 1,
      MAX_WORD_LENGTH = 4,
      MIN_HASH_VALUE = 1,
      MAX_HASH_VALUE = 121
    };

  static const struct operator oplist[] =
    {
      {"", TOK_ERROR},
      {">",	TOK_GREATER},
      {">>",	TOK_SHIFT_RIGHT},
      {">>>",	TOK_DOUBLESHIFT_RIGHT},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {">=",	TOK_GREATEREQUAL},
      {">>=", 	TOK_ASSIGNMENT_OPERATOR_NOEQUAL},
      {">>>=", 	TOK_ASSIGNMENT_OPERATOR_NOEQUAL},
      {"", TOK_ERROR},
      {"=",	TOK_EQUAL},
      {"==",	TOK_EQUAL_EQUAL},
      {"===",	TOK_TRIPLE_EQUAL},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"<=",	TOK_LESSEQUAL},
      {"<<=", 	TOK_ASSIGNMENT_OPERATOR_NOEQUAL},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {"<",	TOK_LESS},
      {"<<",	TOK_SHIFT_LEFT},
      {"/=", 	TOK_ASSIGNMENT_OPERATOR_NOEQUAL},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"|=", 	TOK_ASSIGNMENT_OPERATOR_NOEQUAL},
      {"*=", 	TOK_ASSIGNMENT_OPERATOR_NOEQUAL},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {"~",	TOK_TILDE},
      {"-=", 	TOK_ASSIGNMENT_OPERATOR_NOEQUAL},
      {"/",	TOK_DIVIDE},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"+=", 	TOK_ASSIGNMENT_OPERATOR_NOEQUAL},
      {"%=", 	TOK_ASSIGNMENT_OPERATOR_NOEQUAL},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {"|",	TOK_OR},
      {"||",	TOK_OR_OR},
      {"*",	TOK_MULTIPLY},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"&=", 	TOK_ASSIGNMENT_OPERATOR_NOEQUAL},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"-",	TOK_MINUS},
      {"--",	TOK_MINUSMINUS},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR},
      {"!=",	TOK_NOT_EQUAL},
      {"!==",	TOK_NOT_DOUBLEEQUAL},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {"+",	TOK_PLUS},
      {"++",	TOK_PLUSPLUS},
      {"%",	TOK_PERCENT},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"^=", 	TOK_ASSIGNMENT_OPERATOR_NOEQUAL},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"?",	TOK_QUESTIONMARK},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"&",	TOK_AND},
      {"&&",	TOK_AND_AND},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR},
      {":",	TOK_COLON},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"!",	TOK_EXCLAMATION},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR}, {"", TOK_ERROR}, {"", TOK_ERROR},
      {"", TOK_ERROR},
      {"^",	TOK_XOR}
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      int key = op_hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          const char *s = oplist[key].name;

          if (*str == *s && !strncmp (str + 1, s + 1, len - 1) && s[len] == '\0')
            return &oplist[key];
        }
    }
  return 0;
}
