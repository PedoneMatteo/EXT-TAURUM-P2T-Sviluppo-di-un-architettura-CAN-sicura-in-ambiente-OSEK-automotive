/* ###*B*###
 * ERIKA Enterprise - a tiny RTOS for small microcontrollers
 *
 * Copyright (C) 2002-2008  Evidence Srl
 *
 * This file is part of ERIKA Enterprise.
 *
 * ERIKA Enterprise is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation, 
 * (with a special exception described below).
 *
 * Linking this code statically or dynamically with other modules is
 * making a combined work based on this code.  Thus, the terms and
 * conditions of the GNU General Public License cover the whole
 * combination.
 *
 * As a special exception, the copyright holders of this library give you
 * permission to link this code with independent modules to produce an
 * executable, regardless of the license terms of these independent
 * modules, and to copy and distribute the resulting executable under
 * terms of your choice, provided that you also meet, for each linked
 * independent module, the terms and conditions of the license of that
 * module.  An independent module is a module which is not derived from
 * or based on this library.  If you modify this code, you may extend
 * this exception to your version of the code, but you are not
 * obligated to do so.  If you do not wish to do so, delete this
 * exception statement from your version.
 *
 * ERIKA Enterprise is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with ERIKA Enterprise; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 * ###*E*### */

/*
 * Author: Evidence Srl in collaboration with Lauterbach
 */
#include "ee.h"
#include "ee_irq.h"
#include "board/axiom_mpc5674fxmb/inc/ee_board.h"
#include "aes.h"

//****************************************************************************
// Defines:
//****************************************************************************
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
#define Nk 4        // The number of 32 bit words in a cipher key.
#define Nr 10       // The number of rounds in AES-128 Cipher.

#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif


//****************************************************************************
// Private variables:
//****************************************************************************
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];

// The round constant word array, Rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

//function memcpy added to solve two errors
 void *memcpy(void *dest, const void *src, int n){
	for(int i=0; i<n; i++)
		((char*)dest)[i] = ((char*)src)[i];
 }

//****************************************************************************
// Private functions:
//***************************************************************************

//static uint8_t getSBoxValue(uint8_t num){
//  return sbox[num];}

#define getSBoxValue(num) (sbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
/*#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif*/
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}

void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  for(int i=0; i<AES_BLOCKLEN; i++)
    ctx->Iv[i]=iv[i];
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  for(int i=0; i<AES_BLOCKLEN; i++)
    ctx->Iv[i]=iv[i];
}


// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix


// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); // this last call to xtime() can be omitted
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif



//static uint8_t getSBoxInvert(uint8_t num){
//  return rsbox[num];}

#define getSBoxInvert(num) (rsbox[(num)])

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  {
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}


// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns()
  for (round = 1; ; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  // Add round key to last round
  AddRoundKey(Nr, state, RoundKey);
}


static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without InvMixColumn()
  for (round = (Nr - 1); ; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    if (round == 0) {
      break;
    }
    InvMixColumns(state);
  }

}


//****************************************************************************
// Public functions:
//****************************************************************************

static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
}

void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, int length)
{
  int i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    XorWithIv(buf, Iv);
    Cipher((state_t*)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  // store Iv in ctx for next call
  for(int j=0; j<AES_BLOCKLEN; j++)
    ctx->Iv[j]=Iv[j];

}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, int length)
{
  int i;
  uint8_t storeNextIv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    for(int j=0; j<AES_BLOCKLEN; j++)
      storeNextIv[j]=buf[j];

    InvCipher((state_t*)buf, ctx->RoundKey);
    XorWithIv(buf, ctx->Iv);
    for(int j=0; j<AES_BLOCKLEN; j++)
      ctx->Iv[j]=storeNextIv[j];

    buf += AES_BLOCKLEN;
  }

}



// Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key

static void test_decrypt_cbc(void)
{
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t in[]  = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                      0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                      0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                      0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, in, 64);

}

static void test_encrypt_cbc(void)
{
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in, 64);

}

#define LED_ON	1
#define LED_OFF	0

/* Dummy shared variable used by ALL tasks */
unsigned char dummy_shared_variable = 0;

/* A few counters incremented at each event 
 * (alarm, button press or task activation...)
 */
volatile int timer_fired=0;
volatile int button_fired=0;
volatile int task1_fired=0;
volatile int task2_fired=0;
volatile int task3_fired=0;
volatile int task4_fired=0;
volatile int task5_fired=0;
volatile int task6_fired=0;
volatile int task7_fired=0;

/* Added for a finest debugger (run-time) tuning */
int tunable_delay = 50000;

/* Let's declare the tasks identifiers */
DeclareTask(Task1);
DeclareTask(Task2);
DeclareTask(Task3);
DeclareTask(Task4);
DeclareTask(Task5);
DeclareTask(Task6);
DeclareTask(Task7);

/* Event declaration */
DeclareEvent(TimerEvent);

/* some other prototypes */
void mydelay(long int end);
void led_blink(unsigned char theled);

static void led_on(void)
{
	EE_led_3_on();
	EE_led_7_off();
}

static void led_off(void)
{
	EE_led_3_off();
	EE_led_7_on();
}

/* just a dummy delay */ 
void mydelay(long int end)
{
  	volatile long int i;
  	for (i=0; i<end; i++);
    
  	return;  
}

void led_blink(unsigned char theled)
{
  DisableAllInterrupts();
  EE_led_set(theled, LED_ON);
  EnableAllInterrupts();

  mydelay((long int)tunable_delay);

  DisableAllInterrupts();
  EE_led_set(theled, LED_OFF);
  EnableAllInterrupts();
}

/* Task1: just call the ChristmasTree */
TASK(Task1)
{
  task1_fired++;

  /* First half of the christmas tree */
  led_blink(0);
  led_blink(1);
  led_blink(2);

  /* Second half of the christmas tree */
  led_blink(4);
  led_blink(5);
  led_blink(6);
  
  TerminateTask();
}


/* Task2: blink led3 and led7 */
TASK(Task2)
{
  static int which_led = 0;

  task2_fired++;

  /* First click: led_3 on led_7 off */
  if (which_led) {
	led_on();
    which_led = 0;
  }
  else 
  {
    /* Second click: led_3 off led_7 on */
	led_off();
    which_led = 1;
  }

  TerminateTask();
}

TASK(Task3)
{
  task3_fired++;

  // Lock the resource
  GetResource(Resource);

  // Write to a dummy shared variable
  dummy_shared_variable = 3;

  // Release the lock
  ReleaseResource(Resource);

  // Lock the resource
  GetResource(Resource3);

  // Write to a dummy shared variable
  dummy_shared_variable = 6;

  // Release the lock
  ReleaseResource(Resource3);

  // Lock the resource
  GetResource(Resource2);

  // Write to a dummy shared variable
  dummy_shared_variable = 12;

  // Release the lock
  ReleaseResource(Resource2);
  
  test_encrypt_cbc();

  TerminateTask();
}

TASK(Task4)
{
  task4_fired++;

  /* Lock the resource */
  GetResource(Resource);

  /* Write to a dummy shared variable */
  dummy_shared_variable = 4;

  /* Release the lock */
  ReleaseResource(Resource);

  /* Lock the resource */
  GetResource(Resource3);

  /* Write to a dummy shared variable */
  dummy_shared_variable = 8;

  /* Release the lock */
  ReleaseResource(Resource3);
  
  TerminateTask();
}

TASK(Task5)
{
  task5_fired++;

  test_decrypt_cbc();

  TerminateTask();
}

TASK(Task6)
{
  EventMaskType mask;
  
  while (1) {
    WaitEvent(TimerEvent);
    GetEvent(Task6, &mask);

    if (mask & TimerEvent) {
      ClearEvent(TimerEvent);
    }

    /* Lock the resource */
    GetResource(Resource2);

    /* Write to a dummy shared variable */
    dummy_shared_variable = 24;

    /* Release the lock */
    ReleaseResource(Resource2);
  }

  TerminateTask();
}

TASK(Task7)
{
  /* Lock the resource */
  GetResource(Resource3);

  /* Write to a dummy shared variable */
  dummy_shared_variable = 7;

  /* Release the lock */
  ReleaseResource(Resource3);

  TerminateTask();
}
 
static void Buttons_Interrupt(void)
{
  button_fired++;
  ActivateTask(Task2);

   /* arm an alarm that will activate Task7 */
  SetRelAlarm(AlarmTask2,750,0);

  EE_buttons_clear_ISRflag(BUTTON_0);
}

volatile int timer_divisor = 0;

static void Counter_Interrupt(void)
{
  CounterTick(Counter1);

  timer_divisor++;

  if (timer_divisor == 1) {
    ActivateTask(Task3);
  }
  else if (timer_divisor == 100) {
    ActivateTask(Task4);
  }
  else if (timer_divisor == 200) {
    ActivateTask(Task5);
  }
  else if (timer_divisor==300) {
    timer_divisor = 0;
    timer_fired++;
    ActivateTask(Task1);
  }
  else {
    /* Dummy empty else statement */
  }

  /* reset the decrementer to fire again */
  EE_e200z7_setup_decrementer(2000);
}

static void setup_interrupts(void)
{
  EE_e200z7_register_ISR(46 + 16, Buttons_Interrupt, 15);
  EE_e200z7_register_ISR(10, Counter_Interrupt, 0);
  EE_e200z7_setup_decrementer(2000);
  EE_e200z7_enableIRQ();
}

int main(void)
{
  /* Init devices */
  EE_buttons_init(BUTTON_0,3);
  
  /* Init leds */
  EE_leds_init();
  
  setup_interrupts();
  
  /* let's start the multiprogramming environment...*/
  StartOS(OSDEFAULTAPPMODE);
  
  /* now the background activities... */
  for (;;);
  
  return 0;
}
