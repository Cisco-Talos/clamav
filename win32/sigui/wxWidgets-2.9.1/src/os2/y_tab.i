static char yysccsid[] = "@(#)yaccpar     1.7 (Berkeley) 09/09/90";
#line 2 "parser.y"
#pragma info( none )
   #pragma info( none )
#pragma info( restore )





    
    
    
    
    
    
    
    
    

      typedef unsigned int size_t;


   char * _Builtin __strcat( char *, const char * );
   char * _Builtin __strchr( const char *, int );
   int    _Builtin __strcmp( const char *, const char * );
   char * _Builtin __strcpy( char*, const char * );
   size_t _Builtin __strlen( const char * );
   char * _Builtin __strncat( char *, const char *, size_t );
   int    _Builtin __strncmp( const char *, const char *, size_t );
   char * _Builtin __strncpy( char *, const char *, size_t );
   char * _Builtin __strrchr( const char *, int );

   int    _Import _Optlink strcoll( const char *, const char * );
   size_t _Import _Optlink strcspn( const char *, const char * );
   char * _Import _Optlink strerror( int );
   char * _Import _Optlink strpbrk( const char *, const char * );
   size_t _Import _Optlink strspn( const char *, const char * );
   char * _Import _Optlink strstr( const char *, const char * );
   char * _Import _Optlink strtok( char*, const char * );
   size_t _Import _Optlink strxfrm( char *, const char *, size_t );

      char * _Import _Optlink strcat( char *, const char * );
      char * _Import _Optlink strchr( const char *, int );
      int    _Import _Optlink strcmp( const char *, const char * );
      char * _Import _Optlink strcpy( char *, const char * );
      size_t _Import _Optlink strlen( const char * );
      char * _Import _Optlink strncat( char *, const char *, size_t );
      int    _Import _Optlink strncmp( const char *, const char *, size_t );
      char * _Import _Optlink strncpy( char *, const char *, size_t );
      char * _Import _Optlink strrchr( const char *, int );

      #pragma info( none )
      #pragma info( restore )



      void * _Builtin __memcpy( void *, const void *, size_t );
      void * _Builtin __memchr( const void *, int, size_t );
      int    _Builtin __memcmp( const void *, const void *, size_t );
      void * _Builtin __memset( void *, int, size_t );
      void * _Builtin __memmove( void *, const void *, size_t );

         void * _Import _Optlink memcpy( void *, const void *, size_t );
         void * _Import _Optlink memchr( const void *, int, size_t );
         int    _Import _Optlink memcmp( const void *, const void *, size_t );
         void * _Import _Optlink memset( void *, int, size_t );
         void * _Import _Optlink memmove( void *, const void *, size_t );

         #pragma info( none )
         #pragma info( restore )



         void * _Import _Optlink memccpy( void *, void *, int, unsigned int );
         int    _Import _Optlink memicmp( void *, void *, unsigned int );





      char * _Import _Optlink strdup( const char * );
      int    _Import _Optlink stricmp( const char *, const char * );
      char * _Import _Optlink strlwr( char * );
      int    _Import _Optlink strnicmp( const char *, const char *, size_t );
      char * _Import _Optlink strupr( char * );

      int    _Import _Optlink strcmpi( const char *, const char * );
      char * _Import _Optlink strrev( char * );
      char * _Import _Optlink strset( char *, int );
      char * _Import _Optlink strnset( char *, int, size_t );
      char * _Import _Optlink _strerror( char * );


      size_t _Import _Optlink _fstrcspn( const char *, const char * );
      char * _Import _Optlink _fstrdup( const char * );
      char * _Import _Optlink _nstrdup( const char * );
      int    _Import _Optlink _fstricmp( const char *, const char * );
      char * _Import _Optlink _fstrlwr( char * );
      int    _Import _Optlink _fstrnicmp( const char *, const char *, size_t );
      char * _Import _Optlink _fstrnset( char *, int, size_t );
      char * _Import _Optlink _fstrpbrk( const char *, const char * );
      char * _Import _Optlink _fstrrev( char * );
      char * _Import _Optlink _fstrset( char *, int );
      size_t _Import _Optlink _fstrspn( const char *, const char * );
      char * _Import _Optlink _fstrstr( const char *, const char * );
      char * _Import _Optlink _fstrtok( char*, const char * );
      char * _Import _Optlink _fstrupr( char * );

      #pragma map( _fstrcspn , "strcspn"  )
      #pragma map( _fstrdup  , "strdup"   )
      #pragma map( _nstrdup  , "strdup"   )
      #pragma map( _fstricmp , "stricmp"  )
      #pragma map( _fstrlwr  , "strlwr"   )
      #pragma map( _fstrnicmp, "strnicmp" )
      #pragma map( _fstrnset , "strnset"  )
      #pragma map( _fstrpbrk , "strpbrk"  )
      #pragma map( _fstrrev  , "strrev"   )
      #pragma map( _fstrset  , "strset"   )
      #pragma map( _fstrspn  , "strspn"   )
      #pragma map( _fstrstr  , "strstr"   )
      #pragma map( _fstrtok  , "strtok"   )
      #pragma map( _fstrupr  , "strupr"   )




#pragma info( none )
   #pragma info( restore )
#pragma info( restore )
#pragma info( none )
   #pragma info( none )
#pragma info( restore )





    
    
    
    
    
    
    
    
    


      int  _Import _Optlink _access( const char *, int );
      int  _Import _Optlink _chmod( const char *, int );
      int  _Import _Optlink _chsize( int, long );
      int  _Import _Optlink _close( int );
      int  _Import _Optlink _creat( const char *, int );
      int  _Import _Optlink _dup( int );
      int  _Import _Optlink _dup2( int, int );
      int  _Import _Optlink __eof( int );
      long _Import _Optlink _filelength( int );
      int  _Import _Optlink _isatty( int );
      long _Import _Optlink _lseek( int, long, int );
      int  _Import _Optlink _open( const char *, int, ... );
      int  _Import _Optlink _read( int, void *, unsigned int );
      int  _Import _Optlink remove( const char * );
      int  _Import _Optlink rename( const char *, const char * );
      int  _Import _Optlink _sopen( const char *, int, int, ... );
      long _Import _Optlink _tell( int );
      int  _Import _Optlink _umask( int );
      int  _Import _Optlink _unlink( const char * );
      int  _Import _Optlink _write( int, const void *, unsigned int );
      int  _Import _Optlink _setmode(int handle, int mode);

      int  _Import _Optlink  access( const char *, int );
      int  _Import _Optlink  chmod( const char *, int );
      int  _Import _Optlink  chsize( int, long );
      int  _Import _Optlink  close( int );
      int  _Import _Optlink  creat( const char *, int );
      int  _Import _Optlink  dup( int );
      int  _Import _Optlink  dup2( int, int );
      int  _Import _Optlink  eof( int );
      long _Import _Optlink  filelength( int );
      int  _Import _Optlink  isatty( int );
      long _Import _Optlink  lseek( int, long, int );
      int  _Import _Optlink  open( const char *, int, ... );
      int  _Import _Optlink  read( int, void *, unsigned int );
      int  _Import _Optlink  sopen( const char *, int, int, ... );
      long _Import _Optlink  tell( int );
      int  _Import _Optlink  umask( int );
      int  _Import _Optlink  unlink( const char * );
      int  _Import _Optlink  write( int, const void *, unsigned int );
      int  _Import _Optlink  setmode(int handle, int mode);

      #pragma map( access    , "_access"     )
      #pragma map( chmod     , "_chmod"      )
      #pragma map( chsize    , "_chsize"     )
      #pragma map( close     , "_close"      )
      #pragma map( creat     , "_creat"      )
      #pragma map( dup       , "_dup"        )
      #pragma map( dup2      , "_dup2"       )
      #pragma map( eof       , "__eof"       )
      #pragma map( filelength, "_filelength" )
      #pragma map( isatty    , "_isatty"     )
      #pragma map( lseek     , "_lseek"      )
      #pragma map( open      , "_open"       )
      #pragma map( read      , "_read"       )
      #pragma map( sopen     , "_sopen"      )
      #pragma map( tell      , "_tell"       )
      #pragma map( umask     , "_umask"      )
         #pragma map( unlink    , "_unlink"     )
      #pragma map( write     , "_write"      )
      #pragma map( setmode   , "_setmode"    )




#pragma info( none )
   #pragma info( restore )
#pragma info( restore )

 


#pragma info( none )
   #pragma info( none )
#pragma info( restore )





    
    
    
    
    
    
    
    
    

   extern const double _infinity;

    

      double _Builtin __fabs( double );
         double _Import _Optlink fabs( double );
         #pragma info( none )
         #pragma info( restore )

   double _Import _Optlink atan2( double, double );
   double _Import _Optlink ceil( double );
   double _Import _Optlink cosh( double );
   double _Import _Optlink exp( double );
   double _Import _Optlink floor( double );
   double _Import _Optlink fmod( double, double );
   double _Import _Optlink frexp( double, int * );
   double _Import _Optlink ldexp( double, int );
   double _Import _Optlink log( double );
   double _Import _Optlink log10( double );
   double _Import _Optlink modf( double, double * );
   double _Import _Optlink pow( double, double );
   double _Import _Optlink sinh( double );
   double _Import _Optlink tanh( double );

      double _Import _Optlink asin( double );
      double _Import _Optlink acos( double );
      double _Import _Optlink atan( double );
      double _Import _Optlink sin( double );
      double _Import _Optlink cos( double );
      double _Import _Optlink tan( double );
      double _Import _Optlink sqrt( double );

      double _Import _Optlink _erf( double );
      double _Import _Optlink _erfc( double );
      double _Import _Optlink _gamma( double );
      double _Import _Optlink _hypot( double, double );
      double _Import _Optlink _j0( double );
      double _Import _Optlink _j1( double );
      double _Import _Optlink _jn( int, double );
      double _Import _Optlink _y0( double );
      double _Import _Optlink _y1( double );
      double _Import _Optlink _yn( int, double );
      double _Import _Optlink erf( double );
      double _Import _Optlink erfc( double );
      double _Import _Optlink gamma( double );
      double _Import _Optlink hypot( double, double );
      double _Import _Optlink j0( double );
      double _Import _Optlink j1( double );
      double _Import _Optlink jn( int, double );
      double _Import _Optlink y0( double );
      double _Import _Optlink y1( double );
      double _Import _Optlink yn( int, double );

      #pragma map( erf, "_erf" )
      #pragma map( erfc, "_erfc" )
      #pragma map( gamma, "_gamma" )
      #pragma map( hypot, "_hypot" )
      #pragma map( j0, "_j0" )
      #pragma map( j1, "_j1" )
      #pragma map( jn, "_jn" )
      #pragma map( y0, "_y0" )
      #pragma map( y1, "_y1" )
      #pragma map( yn, "_yn" )

         extern const long double _LHUGE_VAL;



                                           

           struct complex
               {
               double x,y;              
               };

           double      _Import _Optlink _cabs( struct complex );

          #pragma info( none )
          #pragma info( restore )

         struct exception
            {
            int type;                
            char *name;              
            double arg1;             
            double arg2;             
            double retval;           
            };

          

         int _matherr( struct exception * );
         int  matherr( struct exception * );

           #pragma map( matherr, "_matherr" )

         long double _Optlink _atold( const char * );





#pragma info( none )
   #pragma info( restore )
#pragma info( restore )


#pragma info( none )
   #pragma info( none )
#pragma info( restore )





    
    
    
    
    
    
    
    
    


     typedef unsigned short wchar_t;

   typedef struct _div_t
       {
       int quot;         
       int rem;          
       } div_t;

   typedef struct _ldiv_t
       {
       long int quot;    
       long int rem;     
       } ldiv_t;



      typedef unsigned long  _System  _EH_RTN(void *,void *,void *,void *);

   extern int _Import _Optlink _eh_del(_EH_RTN *);
   extern int _Import _Optlink _eh_add(_EH_RTN *);
   extern int _Import _mb_cur_max;

    

   int      _Builtin __abs( int );
   long int _Builtin __labs( long int );

   double   _Import _Optlink atof( const char * );
   int      _Import _Optlink atoi( const char * );
   long int _Import _Optlink atol( const char * );
   double   _Import _Optlink strtod( const char *, char ** );
   long int _Import _Optlink strtol( const char *, char **, int );
   unsigned long int _Import _Optlink strtoul( const char *, char **, int );
   int      _Import _Optlink rand( void );
   void     _Import _Optlink srand( unsigned int );
   void *   (_Import _Optlink calloc)( size_t, size_t );
   void     (_Import _Optlink free)( void * );
   void *   (_Import _Optlink malloc)( size_t );
   void *   (_Import _Optlink realloc)( void *, size_t );
   void     _Import _Optlink abort( void );
   int      _Import _Optlink atexit( void ( * )( void ) );
   void     _Import _Optlink exit( int );
   char *   _Import _Optlink getenv( const char * );
   int      _Import _Optlink system( const char * );
   void *   _Import _Optlink bsearch( const void *, const void *, size_t, size_t,
                              int ( * _Optlink __compare )( const void *, const void * ) );
   void     _Import _Optlink qsort( void *, size_t, size_t,
                            int ( * _Optlink __compare )( const void *, const void * ) );
   div_t    _Import _Optlink div( int, int );
   ldiv_t   _Import _Optlink ldiv( long int, long int );
   int      _Import _Optlink mblen( const char *, size_t );
   int      _Import _Optlink mbtowc( wchar_t *, const char *, size_t );
   int      _Import _Optlink wctomb( char *, wchar_t );
   size_t   _Import _Optlink mbstowcs( wchar_t *, const char *, size_t );
   size_t   _Import _Optlink wcstombs( char *, const wchar_t *, size_t );

      int      _Import _Optlink abs ( int );
      long int _Import _Optlink labs( long int );

      #pragma info( none )
      #pragma info( restore )




         void * _Builtin __alloca( size_t );
         #pragma info( none )
         #pragma info( restore )

      unsigned char _Builtin __parmdwords( void );

      long double _Import _Optlink _atold( const char * );
      char * _Import _Optlink  ecvt( double, int, int *, int * );
      char * _Import _Optlink _ecvt( double, int, int *, int * );
      char * _Import _Optlink  fcvt( double, int, int *, int * );
      char * _Import _Optlink _fcvt( double, int, int *, int * );
      int    _Import _Optlink _freemod( unsigned long );
      char * _Import _Optlink _fullpath(char *, char *, size_t);
      char * _Import _Optlink  gcvt( double, int, char * );
      char * _Import _Optlink _gcvt( double, int, char * );
      int    (_Import _Optlink _heapmin)( void );
      char * _Import _Optlink  itoa( int, char *, int );
      char * _Import _Optlink _itoa( int, char *, int );
      int    _Import _Optlink _loadmod( char *, unsigned long * );
      char * _Import _Optlink  ltoa( long, char *, int );
      char * _Import _Optlink _ltoa( long, char *, int );
      size_t _Import _Optlink _msize(void *);
      int    _Import _Optlink  putenv( const char * );
      int    _Import _Optlink _putenv( const char * );
      long double _Import _Optlink  strtold( const char *, char ** );
      long double _Import _Optlink _strtold( const char *, char ** );
      char * _Import _Optlink  ultoa( unsigned long, char *, int );
      char * _Import _Optlink _ultoa( unsigned long, char *, int );

      #pragma map( ecvt    , "_ecvt"    )
      #pragma map( fcvt    , "_fcvt"    )
      #pragma map( gcvt    , "_gcvt"    )
      #pragma map( itoa    , "_itoa"    )
      #pragma map( ltoa    , "_ltoa"    )
      #pragma map( ultoa   , "_ultoa"   )
      #pragma map( putenv  , "_putenv"  )
      #pragma map( _strtold, "strtold"  )





         int  _Import _Optlink _beginthread( void ( * _Optlink thread )( void * ), void *, unsigned, void * );
         void _Import _Optlink _endthread( void );
         void ** _Import _Optlink _threadstore( void );

      #pragma map( atof  , "_atofieee"   )
      #pragma map( strtod, "_strtodieee" )


         void  _Builtin __enable( void );
         void  _Builtin __disable( void );


               int * _Import _Optlink _errno( void );
               #pragma info( none )
               #pragma info( restore )

               int * _Import _Optlink __doserrno(void);
               #pragma info( none )
               #pragma info( restore )

         extern char ** _Import _environ;
         extern unsigned char _Import _osmajor;
         extern unsigned char _Import _osminor;
         extern unsigned char _Import _osmode;



         typedef int ( __onexit_t )( void );
         typedef __onexit_t * onexit_t;

          
          


         void           _Import _Optlink _exit( int );
         onexit_t       _Import _Optlink  onexit( onexit_t );
         onexit_t       _Import _Optlink _onexit( onexit_t );

         unsigned long  _Builtin  __lrotl(unsigned long, int);
         unsigned long  _Builtin  __lrotr(unsigned long, int);
         unsigned short _Builtin  __srotl(unsigned short, int);
         unsigned short _Builtin  __srotr(unsigned short, int);
         unsigned char  _Builtin  __crotl(unsigned char, int);
         unsigned char  _Builtin  __crotr(unsigned char, int);

         void           _Import _Optlink _makepath( char *, char *, char *, char *, char * );
         void           _Import _Optlink _splitpath( char *, char *, char *, char *, char * );
         void           _Import _Optlink _searchenv( char *, char *, char *);
         void           _Import _Optlink  swab( char *, char *, int );
         void           _Import _Optlink _swab( char *, char *, int );

         #pragma map( onexit , "_onexit"  )
         #pragma map( swab   , "_swab"    )

         int           _Import _Optlink rpmatch(const char *);
         int           _Import _Optlink csid(const char *);
         int           _Import _Optlink wcsid(const wchar_t);

         #pragma map( rpmatch, "_rpmatch" )
         #pragma map( csid   , "_csid"    )
         #pragma map( wcsid  , "_wcsid"   )

          
          






#pragma info( none )
   #pragma info( restore )
#pragma info( restore )



 


 
 

 

char *proio_cons();
char * wxmake_integer();
char * wxmake_word();
char * wxmake_string();
char * wxmake_real();
char * wxmake_exp();
char * wxmake_exp2();

void add_expr();
void process_command();
void syntax_error();

	 



int PROIO_yylex(void);
int PROIO_yylook(void);
int PROIO_yywrap(void);
int PROIO_yyback(int *, int);

 
void PROIO_yyoutput(int);

#line 36 "parser.y"
typedef union {
    char *s;
 
} YYSTYPE;
#line 44 "y_tab.c"
short PROIO_yylhs[] = {                                        -1,
    0,    0,    1,    1,    1,    2,    2,    2,    3,    3,
    3,    4,    4,    5,    5,    5,    5,    5,    5,    5,
};
short PROIO_yylen[] = {                                         2,
    0,    2,    2,    2,    2,    4,    2,    3,    0,    1,
    3,    3,    1,    1,    1,    1,    3,    3,    5,    1,
};
short PROIO_yydefred[] = {                                      1,
    0,    0,    0,    0,    2,    0,    5,    3,    0,    0,
    0,   15,    7,   20,    0,    0,   13,    4,    0,    0,
    0,    0,    8,    0,    6,    0,   18,    0,   12,   11,
    0,   19,
};
short PROIO_yydgoto[] = {                                       1,
    5,   14,   15,   16,   17,
};
short PROIO_yysindex[] = {                                      0,
   -2,    9,    2,    1,    0,   10,    0,    0,   11,   -5,
   17,    0,    0,    0,   14,   -1,    0,    0,   33,   38,
   41,   16,    0,   11,    0,   29,    0,   40,    0,    0,
   44,    0,
};
short PROIO_yyrindex[] = {                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,   42,   21,
   24,    0,    0,    0,    0,   30,    0,    0,    0,    0,
    0,    0,    0,   31,    0,   27,    0,   24,    0,    0,
    0,    0,
};
short PROIO_yygindex[] = {                                      0,
    0,   45,   -8,    0,   26,
};
short PROIO_yytable[] = {                                       3,
   19,   10,   11,   12,   24,    9,    4,   20,   21,    4,
   13,   10,   11,   12,    8,   30,   10,   28,   12,    4,
    9,    7,   18,   23,    4,   16,   16,   22,   14,   14,
   16,   17,   17,   14,   10,    9,   17,   25,   26,   10,
    9,   27,   31,    9,   32,    6,    9,   29,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    2,
};
short PROIO_yycheck[] = {                                       2,
    9,    1,    2,    3,    6,    4,    9,   13,   14,    9,
   10,    1,    2,    3,   13,   24,    1,    2,    3,    9,
    4,   13,   13,   10,    9,    5,    6,   11,    5,    6,
   10,    5,    6,   10,    5,    5,   10,    5,    1,   10,
   10,    1,   14,    4,    1,    1,    5,   22,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  256,
};
int PROIO_yydebug;
int PROIO_yynerrs;
int PROIO_yyerrflag;
int PROIO_yychar;
short *PROIO_yyssp;
YYSTYPE *PROIO_yyvsp;
YYSTYPE PROIO_yyval;
YYSTYPE PROIO_yylval;
short PROIO_yyss[600];
YYSTYPE PROIO_yyvs[600];
#line 118 "parser.y"

 

 


#pragma info( none )
   #pragma info( none )
#pragma info( restore )





    
    
    
    
    
    
    
    
    


   enum _OPERATIONS { _IOINIT, _IOREAD, _IOWRITE, _IOREPOSITION,
                      _IOFLUSH, _IOUNDEFOP };


   #pragma pack( 1 )
   typedef struct __file        
      {
      unsigned char     *_bufPtr;
      unsigned long int  _count;
      unsigned long int  _userFlags;
      unsigned long int  _bufLen;
      unsigned long int  _ungetCount;
      int                _tempStore;
      unsigned char      _ungetBuf[2];
      enum _OPERATIONS   _lastOp;
      char               _filler;
      } FILE;
   #pragma pack( )

   typedef struct __fpos_t       
      {
      long int __fpos_elem[2];
      } fpos_t;




   typedef char *__va_list;


    

   extern FILE * const _Import stdin;
   extern FILE * const _Import stdout;
   extern FILE * const _Import stderr;


    

   int      _Import _Optlink fprintf( FILE *, const char *, ... );
   int      _Import _Optlink fscanf( FILE *, const char *, ... );
   int      _Import _Optlink printf( const char *, ... );
   int      _Import _Optlink scanf( const char *, ... );
   int      _Import _Optlink sprintf( char *, const char *, ... );
   int      _Import _Optlink sscanf( const char *, const char *, ... );
   void     _Import _Optlink clearerr( FILE * );
   int      _Import _Optlink fclose( FILE * );
   int      _Import _Optlink feof( FILE * );
   int      _Import _Optlink ferror( FILE * );
   int      _Import _Optlink fflush( FILE * );
   int      _Import _Optlink fgetc( FILE * );
   int      _Import _Optlink fgetpos( FILE *, fpos_t * );
   char   * _Import _Optlink fgets( char *, int, FILE * );
   FILE   * _Import _Optlink fopen( const char *, const char * );
   int      _Import _Optlink fputc( int, FILE * );
   int      _Import _Optlink fputs( const char *, FILE * );
   size_t   _Import _Optlink fread( void *, size_t, size_t, FILE * );
   FILE   * _Import _Optlink freopen( const char *, const char *, FILE * );
   int      _Import _Optlink fseek( FILE *, long int, int );
   int      _Import _Optlink fsetpos( FILE *, const fpos_t * );
   long int _Import _Optlink ftell( FILE * );
   size_t   _Import _Optlink fwrite( const void *, size_t, size_t, FILE * );
   int              _Optlink getc( FILE * );
   int              _Optlink getchar( void );
   char   * _Import _Optlink gets( char * );
   void     _Import _Optlink perror( const char * );
   int              _Optlink putc( int, FILE * );
   int              _Optlink putchar( int );
   int      _Import _Optlink puts( const char * );
   int      _Import _Optlink remove( const char * );
   int      _Import _Optlink rename( const char *, const char * );
   void     _Import _Optlink rewind( FILE * );
   void     _Import _Optlink setbuf( FILE *, char * );
   int      _Import _Optlink setvbuf( FILE *, char *, int, size_t );
   FILE   * _Import _Optlink tmpfile( void );
   char   * _Import _Optlink tmpnam( char * );
   int      _Import _Optlink ungetc( int, FILE * );
   int      _Import _Optlink vfprintf( FILE *, const char *, __va_list );
   int      _Import _Optlink vprintf( const char *, __va_list );
   int      _Import _Optlink vsprintf( char *, const char *, __va_list );





    




       #pragma map( fprintf, "_fprintfieee" )
       #pragma map( printf , "_printfieee"  )
       #pragma map( sprintf, "_sprintfieee" )
       #pragma map( fscanf , "_fscanfieee"  )
       #pragma map( scanf  , "_scanfieee"   )
       #pragma map( sscanf , "_sscanfieee"  )

      #pragma map( vfprintf, "_vfprintfieee" )
      #pragma map( vprintf , "_vprintfieee"  )
      #pragma map( vsprintf, "_vsprintfieee" )

      int _Optlink _fcloseall( void );
      int _Optlink _rmtmp( void );

      FILE * _Optlink fdopen( int, const char *);
      int    _Optlink fgetchar( void );
      int    _Optlink fileno( FILE * );
      int    _Optlink flushall( void );
      int    _Optlink fputchar( int );
      char * _Optlink tempnam( char *, char * );
      int    _Optlink unlink( const char * );

      FILE * _Optlink _fdopen( int, const char *);
      int    _Optlink _fgetchar( void );
      int    _Optlink _fileno( FILE * );
      int    _Optlink _flushall( void );
      int    _Optlink _fputchar( int );
      char * _Optlink _tempnam( char *, char * );
      int    _Optlink _unlink( const char * );

      int    _Optlink _set_crt_msg_handle( int );

      #pragma map( fdopen  , "_fdopen"   )
      #pragma map( fgetchar, "_fgetchar" )
      #pragma map( fileno  , "_fileno"   )
      #pragma map( flushall, "_flushall" )
      #pragma map( fputchar, "_fputchar" )
      #pragma map( tempnam , "_tempnam"  )




#pragma info( none )
   #pragma info( restore )
#pragma info( restore )


 









 
 

int read();


 

 

 

 
 

 

 

 

 


 
int PROIO_yywrap(void) { return 1; }


 

 

 

 

 



typedef struct yy_buffer_state *YY_BUFFER_STATE;

# line 1 "lexer.l"
# line 9 "lexer.l"
 
#pragma info( none )
   #pragma info( none )
#pragma info( restore )


#pragma info( none )
   #pragma info( restore )
#pragma info( restore )

 

 

 

	 


static size_t lex_buffer_length = 0;
static  char *lex_buffer = 0;
static size_t lex_string_ptr = 0;
static int lex_read_from_string = 0;

static int my_input(void);
static int my_unput(char);


# line 58 "lexer.l"

 


 



struct yy_buffer_state
    {
    FILE *yy_input_file;

    unsigned char *yy_ch_buf;		 
    unsigned char *yy_buf_pos;	 

     
    int yy_buf_size;	

     
    int yy_n_chars;

    int yy_eof_status;		 
     
    };

static YY_BUFFER_STATE yy_current_buffer;

 


 
static unsigned char yy_hold_char;

static int yy_n_chars;		 





extern unsigned char *PROIO_yytext;
extern int PROIO_yyleng;
extern FILE *PROIO_yyin, *PROIO_yyout;

unsigned char *PROIO_yytext;
int PROIO_yyleng;

FILE *PROIO_yyin = (FILE *) 0, *PROIO_yyout = (FILE *) 0;

typedef int yy_state_type;
static  short int yy_accept[34] =
    {   0,
        0,    0,   18,   16,   13,   14,   16,   16,    6,    7,
       16,    8,   12,   16,    1,   11,    3,    9,   10,    2,
        0,    5,    0,    0,    0,    4,    1,   15,    3,    5,
        0,    0,    0
    } ;

static  unsigned char yy_ec[256] =
    {   0,
        1,    1,    1,    1,    1,    1,    1,    1,    2,    3,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    2,    1,    4,    1,    1,    1,    1,    5,    6,
        7,    8,    9,   10,    9,   11,   12,   13,   13,   13,
       13,   13,   13,   13,   13,   13,   13,    1,    1,    1,
       14,    1,    1,    1,   15,   15,   15,   15,   15,   15,
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,
       16,   17,   18,    1,   15,    1,   15,   15,   15,   15,

       19,   15,   15,   15,   15,   15,   15,   15,   15,   15,
       15,   15,   15,   15,   15,   15,   15,   15,   15,   15,
       15,   15,    1,   20,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,

        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1
    } ;

static  unsigned char yy_meta[21] =
    {   0,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    2,    1,    2,    1,    3,    1,    2,    1
    } ;

static  short int yy_base[37] =
    {   0,
        0,    0,   48,   55,   55,   55,   17,   42,   55,   55,
       19,   55,   55,   23,   17,   55,    0,   55,   55,    0,
       18,   55,   19,   23,   21,   55,   12,   55,    0,   24,
       25,   29,   55,   49,   52,   22
    } ;

static  short int yy_def[37] =
    {   0,
       33,    1,   33,   33,   33,   33,   34,   35,   33,   33,
       33,   33,   33,   33,   33,   33,   36,   33,   33,   36,
       34,   33,   34,   34,   35,   33,   33,   33,   36,   34,
       34,   34,    0,   33,   33,   33
    } ;

static  short int yy_nxt[76] =
    {   0,
        4,    5,    6,    7,    8,    9,   10,    4,   11,   12,
       13,   14,   15,   16,   17,   18,    4,   19,   20,    4,
       22,   22,   30,   29,   27,   26,   22,   22,   30,   27,
       28,   27,   30,   23,   23,   23,   24,   24,   24,   31,
       23,   32,   24,   24,   24,   23,   26,   33,   24,   21,
       21,   21,   25,   25,    3,   33,   33,   33,   33,   33,
       33,   33,   33,   33,   33,   33,   33,   33,   33,   33,
       33,   33,   33,   33,   33
    } ;

static  short int yy_chk[76] =
    {   0,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
        7,   21,   23,   36,   27,   25,   24,   30,   31,   15,
       14,   11,   32,    7,   21,   23,    7,   21,   23,   24,
       30,   31,   24,   30,   31,   32,    8,    3,   32,   34,
       34,   34,   35,   35,   33,   33,   33,   33,   33,   33,
       33,   33,   33,   33,   33,   33,   33,   33,   33,   33,
       33,   33,   33,   33,   33
    } ;

static yy_state_type yy_last_accepting_state;
static unsigned char *yy_last_accepting_cpos;

 

 
 
static unsigned char *yy_c_buf_p = (unsigned char *) 0;
static int yy_init = 1;		 
static int yy_start = 0;	 

 
static int yy_did_buffer_switch_on_eof;

static yy_state_type yy_get_previous_state ();
static yy_state_type yy_try_NUL_trans ();
static int yy_get_next_buffer ();
static void yyunput ();
void PROIO_yyrestart ();
void PROIO_yy_switch_to_buffer ();
void PROIO_yy_load_buffer_state ();
YY_BUFFER_STATE PROIO_yy_create_buffer ();
void PROIO_yy_delete_buffer ();
void PROIO_yy_init_buffer ();


static int input ();

int PROIO_yylex ()
    {
    register yy_state_type yy_current_state;
    register unsigned char *yy_cp, *yy_bp;
    register int yy_act;




    if ( yy_init )
	{
	;

	if ( ! yy_start )
	    yy_start = 1;	 

	if ( ! PROIO_yyin )
	    PROIO_yyin = stdin;

	if ( ! PROIO_yyout )
	    PROIO_yyout = stdout;

	if ( yy_current_buffer )
	    PROIO_yy_init_buffer( yy_current_buffer, PROIO_yyin );
	else
	    yy_current_buffer = PROIO_yy_create_buffer( PROIO_yyin, (8192 * 2) );

	PROIO_yy_load_buffer_state();

	yy_init = 0;
	}

    while ( 1 )		 
	{
	yy_cp = yy_c_buf_p;

	 
	*yy_cp = yy_hold_char;

	 
	yy_bp = yy_cp;

	yy_current_state = yy_start;
yy_match:
	do
	    {
	    register unsigned char yy_c = yy_ec[*yy_cp];
	    if ( yy_accept[yy_current_state] )
		{
		yy_last_accepting_state = yy_current_state;
		yy_last_accepting_cpos = yy_cp;
		}
	    while ( yy_chk[yy_base[yy_current_state] + yy_c] != yy_current_state )
		{
		yy_current_state = yy_def[yy_current_state];
		if ( yy_current_state >= 34 )
		    yy_c = yy_meta[yy_c];
		}
	    yy_current_state = yy_nxt[yy_base[yy_current_state] + yy_c];
	    ++yy_cp;
	    }
	while ( yy_current_state != 33 );
	yy_cp = yy_last_accepting_cpos;
	yy_current_state = yy_last_accepting_state;

yy_find_action:
	yy_act = yy_accept[yy_current_state];

	PROIO_yytext = yy_bp; PROIO_yyleng = yy_cp - yy_bp; yy_hold_char = *yy_cp; *yy_cp = '\0'; yy_c_buf_p = yy_cp;;
	;

do_action:	 


	switch ( yy_act )
	    {
	    case 0:  
	     
	    *yy_cp = yy_hold_char;
	    yy_cp = yy_last_accepting_cpos;
	    yy_current_state = yy_last_accepting_state;
	    goto yy_find_action;

case 1:
# line 60 "lexer.l"
{PROIO_yylval.s = strdup(( char*) PROIO_yytext); return 1;;}
	break;
case 2:
# line 62 "lexer.l"
return 14;;
	break;
case 3:
# line 64 "lexer.l"
{PROIO_yylval.s = strdup(( char*) PROIO_yytext); return 2;;}
	break;
case 4:
# line 66 "lexer.l"
{int len = __strlen( (( char*) PROIO_yytext) );
                                   PROIO_yytext[len-1] = 0;
                                   PROIO_yylval.s = strdup(( char*) (PROIO_yytext+1));
                                   return 2;;}
	break;
case 5:
# line 71 "lexer.l"
{PROIO_yylval.s = strdup(( char*) PROIO_yytext); return 3;;}
	break;
case 6:
# line 73 "lexer.l"
return 4;;
	break;
case 7:
# line 75 "lexer.l"
return 5;;
	break;
case 8:
# line 77 "lexer.l"
return 6;;
	break;
case 9:
# line 79 "lexer.l"
return 9;;
	break;
case 10:
# line 81 "lexer.l"
return 10;;
	break;
case 11:
# line 83 "lexer.l"
return 11;;
	break;
case 12:
# line 85 "lexer.l"
return 13;;
	break;
case 13:
# line 87 "lexer.l"
;
	break;
case 14:
# line 89 "lexer.l"
;
	break;
case 15:
# line 91 "lexer.l"
{       loop:
                          while (input() != '*');
                          switch (input())
                                  {
                                  case '/': break;
                                  case '*': yyunput( '*', PROIO_yytext );
                                  default: goto loop;
                                  }
                          }
	break;
case 16:
# line 106 "lexer.l"
return 8;;
	break;
case 17:
# line 108 "lexer.l"
(void) fwrite( (char *) PROIO_yytext, PROIO_yyleng, 1, PROIO_yyout );
	break;
case (18 + 0 + 1):
    return ( 0 );

	    case 18:
		{
		 
		int yy_amount_of_matched_text = yy_cp - PROIO_yytext - 1;

		 
		*yy_cp = yy_hold_char;

		 
		if ( yy_c_buf_p <= &yy_current_buffer->yy_ch_buf[yy_n_chars] )
		     
		    {
		    yy_state_type yy_next_state;

		    yy_c_buf_p = PROIO_yytext + yy_amount_of_matched_text;

		    yy_current_state = yy_get_previous_state();

		     

		    yy_next_state = yy_try_NUL_trans( yy_current_state );

		    yy_bp = PROIO_yytext + 0;

		    if ( yy_next_state )
			{
			 
			yy_cp = ++yy_c_buf_p;
			yy_current_state = yy_next_state;
			goto yy_match;
			}

		    else
			{
			    yy_cp = yy_last_accepting_cpos;
			    yy_current_state = yy_last_accepting_state;
			goto yy_find_action;
			}
		    }

		else switch ( yy_get_next_buffer() )
		    {
		    case 1:
			{
			yy_did_buffer_switch_on_eof = 0;

			if ( PROIO_yywrap() )
			    {
			     
			    yy_c_buf_p = PROIO_yytext + 0;

			    yy_act = (18 + (yy_start - 1) / 2 + 1);
			    goto do_action;
			    }

			else
			    {
			    if ( ! yy_did_buffer_switch_on_eof )
				do { PROIO_yy_init_buffer( yy_current_buffer, PROIO_yyin ); PROIO_yy_load_buffer_state(); } while ( 0 );
			    }
			}
			break;

		    case 0:
			yy_c_buf_p = PROIO_yytext + yy_amount_of_matched_text;

			yy_current_state = yy_get_previous_state();

			yy_cp = yy_c_buf_p;
			yy_bp = PROIO_yytext + 0;
			goto yy_match;

		    case 2:
			yy_c_buf_p =
			    &yy_current_buffer->yy_ch_buf[yy_n_chars];

			yy_current_state = yy_get_previous_state();

			yy_cp = yy_c_buf_p;
			yy_bp = PROIO_yytext + 0;
			goto yy_find_action;
		    }
		break;
		}

	    default:
		do { (void) fputs( "fatal flex scanner internal error--no action found", stderr ); (void) fputc( ('\n'), (stderr) ); exit( 1 ); } while ( 0 );
	    }
	}
    }


 

static int yy_get_next_buffer()

    {
    register unsigned char *dest = yy_current_buffer->yy_ch_buf;
    register unsigned char *source = PROIO_yytext - 1;  
    register int number_to_move, i;
    int ret_val;

    if ( yy_c_buf_p > &yy_current_buffer->yy_ch_buf[yy_n_chars + 1] )
	do { (void) fputs( "fatal flex scanner internal error--end of buffer missed", stderr ); (void) fputc( ('\n'), (stderr) ); exit( 1 ); } while ( 0 );

     

     
    number_to_move = yy_c_buf_p - PROIO_yytext;

    for ( i = 0; i < number_to_move; ++i )
	*(dest++) = *(source++);

    if ( yy_current_buffer->yy_eof_status != 0 )
	 
	yy_n_chars = 0;

    else
	{
	int num_to_read = yy_current_buffer->yy_buf_size - number_to_move - 1;

	if ( num_to_read > 8192 )
	    num_to_read = 8192;

	else if ( num_to_read <= 0 )
	    do { (void) fputs( "fatal error - scanner input buffer overflow", stderr ); (void) fputc( ('\n'), (stderr) ); exit( 1 ); } while ( 0 );

	 
	if (lex_read_from_string) { int c = my_input(); yy_n_chars = (c == 0) ? 0 : (((&yy_current_buffer->yy_ch_buf[number_to_move]))[0]=(c), 1); } else if ( (yy_n_chars = read( fileno(PROIO_yyin), (char *) (&yy_current_buffer->yy_ch_buf[number_to_move]), num_to_read )) < 0 ) do { (void) fputs( "read() in flex scanner failed", stderr ); (void) fputc( ('\n'), (stderr) ); exit( 1 ); } while ( 0 );;
	}

    if ( yy_n_chars == 0 )
	{
	if ( number_to_move == 1 )
	    {
	    ret_val = 1;
	    yy_current_buffer->yy_eof_status = 2;
	    }

	else
	    {
	    ret_val = 2;
	    yy_current_buffer->yy_eof_status = 1;
	    }
	}

    else
	ret_val = 0;

    yy_n_chars += number_to_move;
    yy_current_buffer->yy_ch_buf[yy_n_chars] = 0;
    yy_current_buffer->yy_ch_buf[yy_n_chars + 1] = 0;

     

    PROIO_yytext = &yy_current_buffer->yy_ch_buf[1];

    return ( ret_val );
    }


 

static yy_state_type yy_get_previous_state()

    {
    register yy_state_type yy_current_state;
    register unsigned char *yy_cp;

    yy_current_state = yy_start;

    for ( yy_cp = PROIO_yytext + 0; yy_cp < yy_c_buf_p; ++yy_cp )
	{
	register unsigned char yy_c = (*yy_cp ? yy_ec[*yy_cp] : 1);
	if ( yy_accept[yy_current_state] )
	    {
	    yy_last_accepting_state = yy_current_state;
	    yy_last_accepting_cpos = yy_cp;
	    }
	while ( yy_chk[yy_base[yy_current_state] + yy_c] != yy_current_state )
	    {
	    yy_current_state = yy_def[yy_current_state];
	    if ( yy_current_state >= 34 )
		yy_c = yy_meta[yy_c];
	    }
	yy_current_state = yy_nxt[yy_base[yy_current_state] + yy_c];
	}

    return ( yy_current_state );
    }


 

static yy_state_type yy_try_NUL_trans( yy_current_state )
register yy_state_type yy_current_state;

    {
    register int yy_is_jam;
    register unsigned char *yy_cp = yy_c_buf_p;

    register unsigned char yy_c = 1;
    if ( yy_accept[yy_current_state] )
	{
	yy_last_accepting_state = yy_current_state;
	yy_last_accepting_cpos = yy_cp;
	}
    while ( yy_chk[yy_base[yy_current_state] + yy_c] != yy_current_state )
	{
	yy_current_state = yy_def[yy_current_state];
	if ( yy_current_state >= 34 )
	    yy_c = yy_meta[yy_c];
	}
    yy_current_state = yy_nxt[yy_base[yy_current_state] + yy_c];
    yy_is_jam = (yy_current_state == 33);

    return ( yy_is_jam ? 0 : yy_current_state );
    }


static void yyunput( c, yy_bp )
unsigned char c;
register unsigned char *yy_bp;

    {
    register unsigned char *yy_cp = yy_c_buf_p;

     
    *yy_cp = yy_hold_char;

    if ( yy_cp < yy_current_buffer->yy_ch_buf + 2 )
	{  
	register int number_to_move = yy_n_chars + 2;  
	register unsigned char *dest =
	    &yy_current_buffer->yy_ch_buf[yy_current_buffer->yy_buf_size + 2];
	register unsigned char *source =
	    &yy_current_buffer->yy_ch_buf[number_to_move];

	while ( source > yy_current_buffer->yy_ch_buf )
	    *--dest = *--source;

	yy_cp += dest - source;
	yy_bp += dest - source;
	yy_n_chars = yy_current_buffer->yy_buf_size;

	if ( yy_cp < yy_current_buffer->yy_ch_buf + 2 )
	    do { (void) fputs( "flex scanner push-back overflow", stderr ); (void) fputc( ('\n'), (stderr) ); exit( 1 ); } while ( 0 );
	}

    if ( yy_cp > yy_bp && yy_cp[-1] == '\n' )
	yy_cp[-2] = '\n';

    *--yy_cp = c;

     
    PROIO_yytext = yy_bp; PROIO_yyleng = yy_cp - yy_bp; yy_hold_char = *yy_cp; *yy_cp = '\0'; yy_c_buf_p = yy_cp;;  
    }


static int input()

    {
    int c;
    unsigned char *yy_cp = yy_c_buf_p;

    *yy_cp = yy_hold_char;

    if ( *yy_c_buf_p == 0 )
	{
	 
	if ( yy_c_buf_p < &yy_current_buffer->yy_ch_buf[yy_n_chars] )
	     
	    *yy_c_buf_p = '\0';

	else
	    {  
	    PROIO_yytext = yy_c_buf_p;
	    ++yy_c_buf_p;

	    switch ( yy_get_next_buffer() )
		{
		case 1:
		    {
		    if ( PROIO_yywrap() )
			{
			yy_c_buf_p = PROIO_yytext + 0;
			return ( (-1) );
			}

		    do { PROIO_yy_init_buffer( yy_current_buffer, PROIO_yyin ); PROIO_yy_load_buffer_state(); } while ( 0 );

		    return ( input() );
		    }
		    break;

		case 0:
		    yy_c_buf_p = PROIO_yytext + 0;
		    break;

		case 2:
		    do { (void) fputs( "unexpected last match in input()", stderr ); (void) fputc( ('\n'), (stderr) ); exit( 1 ); } while ( 0 );
		}
	    }
	}

    c = *yy_c_buf_p;
    yy_hold_char = *++yy_c_buf_p;

    return ( c );
    }


void PROIO_yyrestart( input_file )
FILE *input_file;

    {
    PROIO_yy_init_buffer( yy_current_buffer, input_file );
    PROIO_yy_load_buffer_state();
    }


void PROIO_yy_switch_to_buffer( new_buffer )
YY_BUFFER_STATE new_buffer;

    {
    if ( yy_current_buffer == new_buffer )
	return;

    if ( yy_current_buffer )
	{
	 
	*yy_c_buf_p = yy_hold_char;
	yy_current_buffer->yy_buf_pos = yy_c_buf_p;
	yy_current_buffer->yy_n_chars = yy_n_chars;
	}

    yy_current_buffer = new_buffer;
    PROIO_yy_load_buffer_state();

     
    yy_did_buffer_switch_on_eof = 1;
    }


void PROIO_yy_load_buffer_state()

    {
    yy_n_chars = yy_current_buffer->yy_n_chars;
    PROIO_yytext = yy_c_buf_p = yy_current_buffer->yy_buf_pos;
    PROIO_yyin = yy_current_buffer->yy_input_file;
    yy_hold_char = *yy_c_buf_p;
    }


YY_BUFFER_STATE PROIO_yy_create_buffer( file, size )
FILE *file;
int size;

    {
    YY_BUFFER_STATE b;

    b = (YY_BUFFER_STATE) malloc( sizeof( struct yy_buffer_state ) );

    if ( ! b )
	do { (void) fputs( "out of dynamic memory in yy_create_buffer()", stderr ); (void) fputc( ('\n'), (stderr) ); exit( 1 ); } while ( 0 );

    b->yy_buf_size = size;

     
    b->yy_ch_buf = (unsigned char *) malloc( (unsigned) (b->yy_buf_size + 2) );

    if ( ! b->yy_ch_buf )
	do { (void) fputs( "out of dynamic memory in yy_create_buffer()", stderr ); (void) fputc( ('\n'), (stderr) ); exit( 1 ); } while ( 0 );

    PROIO_yy_init_buffer( b, file );

    return ( b );
    }


void PROIO_yy_delete_buffer( b )
YY_BUFFER_STATE b;

    {
    if ( b == yy_current_buffer )
	yy_current_buffer = (YY_BUFFER_STATE) 0;

    free( (char *) b->yy_ch_buf );
    free( (char *) b );
    }


void PROIO_yy_init_buffer( b, file )
YY_BUFFER_STATE b;
FILE *file;

    {
    b->yy_input_file = file;

     

    b->yy_ch_buf[0] = '\n';
    b->yy_n_chars = 1;

     
    b->yy_ch_buf[1] = 0;
    b->yy_ch_buf[2] = 0;

    b->yy_buf_pos = &b->yy_ch_buf[1];

    b->yy_eof_status = 0;
    }
# line 108 "lexer.l"



static int lex_input() {
  return input();
}

  
void LexFromFile(FILE *fd)
{
  lex_read_from_string = 0;
  PROIO_yyin = fd;
   
  yy_init = 1;
}

void LexFromString(char *buffer)
{
  lex_read_from_string = 1;
  lex_buffer = buffer;
  lex_buffer_length = __strlen( (( char*) buffer) );
  lex_string_ptr = 0;
   
  yy_init = 1;
}

static int my_input( void )
{
  if (lex_read_from_string) {
    if (lex_string_ptr == lex_buffer_length)
      return 0;
    else {
      char c = lex_buffer[lex_string_ptr++];
      return c;
    }
  } else {
    return lex_input();
  }
}

void wxExprCleanUp()
{
	if (yy_current_buffer)
		PROIO_yy_delete_buffer(yy_current_buffer);
}

 

 

void PROIO_yyerror(char *s)
{
  syntax_error(s);
}

 

 

int PROIO_yywrap() { return 1; }
#line 247 "y_tab.c"
int
PROIO_yyparse()
{
    register int yym, yyn, yystate;

    PROIO_yynerrs = 0;
    PROIO_yyerrflag = 0;
    PROIO_yychar = (-1);

    PROIO_yyssp = PROIO_yyss;
    PROIO_yyvsp = PROIO_yyvs;
    *PROIO_yyssp = yystate = 0;

yyloop:
    if (yyn = PROIO_yydefred[yystate]) goto yyreduce;
    if (PROIO_yychar < 0)
    {
        if ((PROIO_yychar = PROIO_yylex()) < 0) PROIO_yychar = 0;
    }
    if ((yyn = PROIO_yysindex[yystate]) && (yyn += PROIO_yychar) >= 0 &&
            yyn <= 254 && PROIO_yycheck[yyn] == PROIO_yychar)
    {
        if (PROIO_yyssp >= PROIO_yyss + 600 - 1)
        {
            goto yyoverflow;
        }
        *++PROIO_yyssp = yystate = PROIO_yytable[yyn];
        *++PROIO_yyvsp = PROIO_yylval;
        PROIO_yychar = (-1);
        if (PROIO_yyerrflag > 0)  --PROIO_yyerrflag;
        goto yyloop;
    }
    if ((yyn = PROIO_yyrindex[yystate]) && (yyn += PROIO_yychar) >= 0 &&
            yyn <= 254 && PROIO_yycheck[yyn] == PROIO_yychar)
    {
        yyn = PROIO_yytable[yyn];
        goto yyreduce;
    }
    if (PROIO_yyerrflag) goto yyinrecovery;
yynewerror:
    PROIO_yyerror("syntax error");
yyerrlab:
    ++PROIO_yynerrs;
yyinrecovery:
    if (PROIO_yyerrflag < 3)
    {
        PROIO_yyerrflag = 3;
        for (;;)
        {
            if ((yyn = PROIO_yysindex[*PROIO_yyssp]) && (yyn += 256) >= 0 &&
                    yyn <= 254 && PROIO_yycheck[yyn] == 256)
            {
                if (PROIO_yyssp >= PROIO_yyss + 600 - 1)
                {
                    goto yyoverflow;
                }
                *++PROIO_yyssp = yystate = PROIO_yytable[yyn];
                *++PROIO_yyvsp = PROIO_yylval;
                goto yyloop;
            }
            else
            {
                if (PROIO_yyssp <= PROIO_yyss) goto yyabort;
                --PROIO_yyssp;
                --PROIO_yyvsp;
            }
        }
    }
    else
    {
        if (PROIO_yychar == 0) goto yyabort;
        PROIO_yychar = (-1);
        goto yyloop;
    }
yyreduce:
    yym = PROIO_yylen[yyn];
    PROIO_yyval = PROIO_yyvsp[1-yym];
    switch (yyn)
    {
case 3:
#line 68 "parser.y"
{process_command(proio_cons(wxmake_word(PROIO_yyvsp[-1].s), 0)); free(PROIO_yyvsp[-1].s);}
break;
case 4:
#line 70 "parser.y"
{process_command(PROIO_yyvsp[-1].s);}
break;
case 5:
#line 72 "parser.y"
{syntax_error("Unrecognized command.");}
break;
case 6:
#line 76 "parser.y"
{PROIO_yyval.s = proio_cons(wxmake_word(PROIO_yyvsp[-3].s), PROIO_yyvsp[-1].s); free(PROIO_yyvsp[-3].s);}
break;
case 7:
#line 78 "parser.y"
{PROIO_yyval.s = proio_cons(0, 0);}
break;
case 8:
#line 80 "parser.y"
{PROIO_yyval.s = PROIO_yyvsp[-1].s; }
break;
case 9:
#line 84 "parser.y"
{PROIO_yyval.s = 0;}
break;
case 10:
#line 86 "parser.y"
{PROIO_yyval.s = proio_cons(PROIO_yyvsp[0].s, 0);}
break;
case 11:
#line 89 "parser.y"
{PROIO_yyval.s = proio_cons(PROIO_yyvsp[-2].s, PROIO_yyvsp[0].s);}
break;
case 12:
#line 93 "parser.y"
{PROIO_yyval.s = proio_cons(wxmake_word("="), proio_cons(wxmake_word(PROIO_yyvsp[-2].s), proio_cons(PROIO_yyvsp[0].s, 0)));
                         free(PROIO_yyvsp[-2].s); }
break;
case 13:
#line 96 "parser.y"
{PROIO_yyval.s = PROIO_yyvsp[0].s; }
break;
case 14:
#line 99 "parser.y"
{PROIO_yyval.s = wxmake_word(PROIO_yyvsp[0].s); free(PROIO_yyvsp[0].s);}
break;
case 15:
#line 101 "parser.y"
{PROIO_yyval.s = wxmake_string(PROIO_yyvsp[0].s); free(PROIO_yyvsp[0].s);}
break;
case 16:
#line 103 "parser.y"
{PROIO_yyval.s = wxmake_integer(PROIO_yyvsp[0].s); free(PROIO_yyvsp[0].s);}
break;
case 17:
#line 105 "parser.y"
{PROIO_yyval.s = wxmake_real(PROIO_yyvsp[-2].s, PROIO_yyvsp[0].s); free(PROIO_yyvsp[-2].s); free(PROIO_yyvsp[0].s); }
break;
case 18:
#line 107 "parser.y"
{PROIO_yyval.s = wxmake_exp(PROIO_yyvsp[-2].s, PROIO_yyvsp[0].s); free(PROIO_yyvsp[-2].s); free(PROIO_yyvsp[0].s); }
break;
case 19:
#line 110 "parser.y"
{PROIO_yyval.s = wxmake_exp2(PROIO_yyvsp[-4].s, PROIO_yyvsp[-2].s, PROIO_yyvsp[0].s); free(PROIO_yyvsp[-4].s); free(PROIO_yyvsp[-2].s);
                                                                  free(PROIO_yyvsp[0].s); }
break;
case 20:
#line 114 "parser.y"
{PROIO_yyval.s = PROIO_yyvsp[0].s;}
break;
#line 461 "y_tab.c"
    }
    PROIO_yyssp -= yym;
    yystate = *PROIO_yyssp;
    PROIO_yyvsp -= yym;
    yym = PROIO_yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
        yystate = 1;
        *++PROIO_yyssp = 1;
        *++PROIO_yyvsp = PROIO_yyval;
        if (PROIO_yychar < 0)
        {
            if ((PROIO_yychar = PROIO_yylex()) < 0) PROIO_yychar = 0;
        }
        if (PROIO_yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = PROIO_yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= 254 && PROIO_yycheck[yyn] == yystate)
        yystate = PROIO_yytable[yyn];
    else
        yystate = PROIO_yydgoto[yym];
    if (PROIO_yyssp >= PROIO_yyss + 600 - 1)
    {
        goto yyoverflow;
    }
    *++PROIO_yyssp = yystate;
    *++PROIO_yyvsp = PROIO_yyval;
    goto yyloop;
yyoverflow:
    PROIO_yyerror("yacc stack overflow");
yyabort:
    return (1);
yyaccept:
    return (0);
}
