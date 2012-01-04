#ifndef H__RIJNDAEL
#define H__RIJNDAEL

int rijndaelSetupDecrypt(unsigned long *rk, const unsigned char *key,
  int keybits);
void rijndaelDecrypt(const unsigned long *rk, int nrounds,
  const unsigned char ciphertext[16], unsigned char plaintext[16]);

#define KEYLENGTH(keybits) ((keybits)/8)
#define RKLENGTH(keybits)  ((keybits)/8+28)
#define NROUNDS(keybits)   ((keybits)/32+6)

#endif

