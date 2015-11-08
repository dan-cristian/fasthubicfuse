/*                         MaGIC.h                     23-11-89 
 *
 *    This is the header file for the parallel version of MaGIC
 *    (Matrix Generator for Implication Connectives) written to run
 *    on a shared memory multiprocessor such as the Sequent Symmetry.
 *    The parent program uses the Portable Monitor Macro Package
 *    developed at Argonne National Laboratories.  MaGIC is intended
 *    to give a choice of front ends: there is at least a simple TTY
 *    version which is supposed to work on just about anything and an
 *    X Windows version designed to be as portable as the Windows 
 *    themselves and written in the first instance for a Sun 3/50 
 *    hanging off the Sequent.  The matrix generator itself uses the
 *    "transferred refutations" algorithm developed at ANU.  At the 
 *    limits of size of matrix for which MaGIC is appropriate this 
 *    algorithm is two orders of magnitude faster than the second-
 *    best method known to us at the date of writing.
 *
 *    The same header is used for the sequential version, since apart
 *    from some superfluous definitions the two programs are alike at 
 *    this level.  The first thing to define is the version and 
 *    release number.
 */ 

#ifdef PARALLEL
#define VERSION "1.1P"
#else
#define VERSION "1.1"
#endif

/***
 ***  For use of TRANSREF it is necessary to define SZ (the number
 ***  of possible values) and V_LENGTH (the maximum length of the
 ***  vectors of values) in the parent program.
 ***/

#define SZ 16
#define V_LENGTH ((SZ*SZ)+1)


/***
 ***  The input data files are all in a directory:
 ***/

#ifdef sequent
#define DEFAULT_DD "/u/jks/mstuff/"
#else
#define DEFAULT_DD "/home/arp/jks/mstuff/"
#endif

#ifndef DATA_DIR
#define DATA_DIR DEFAULT_DD
#endif


/***
 ***  Next the bounds for various arrays. These are the maxima for
 ***  pre-defined axioms (AXMAX), user-defined connectives (CMAX), 
 ***  (sub)formulae (FMAX), testable formulae (TMAX), isomorphs
 ***  per slave (ISOMAX), sub-problems(PROBMAX) and finally matrices 
 ***  on the blackboard (MMAX the general pool, MBMAX the matrix 
 ***  buffer for the critical case) for communicating results to the
 ***  master.
 ***/

#define AXMAX 20
#define CMAX 10
#define FMAX 100
#define TMAX 5
#define ISOMAX 2000
#define PROBMAX 1000
#define MMAX 3500
#define MBMAX 200


/***
 ***  Now the output codes.  This is just an enumeration.
 ***/

#define NONE 0
#define PRETTY 1
#define UGLY 2
#define SUMMARY 3


/***
 ***  Include the usual headers.
 ***/

#include <stdio.h>
#include <ctype.h>


/***
 ***  It remains to define the structure types used.  First (and
 ***  trivially) each "struct xxxtype" expression is abbreviated
 ***  to preserve sanity later on.  Then they are defined.  JOB 
 ***  is for communication of the major problem specification
 ***  between the front end and MaGIC itself.  The others are 
 ***  fairly self-explanatory, except that two versions of the
 ***  formula type are needed, SBF being used by the various slave
 ***  processes for testing purposes and WFF being appropriate to
 ***  the parser.
 ***/

#define JOB struct jobtype
#define ISM struct isomorph
#define WFF struct well_formed_formula
#define SBF struct subformula
#define PRM struct permutation
#define MATRIX struct l_matrix

ISM { char ic[SZ][SZ];         /* Isomorphic version of array C   */
      ISM  *left, *right,
           *parent;            /* Links to make a binary tree     */
    } ;

WFF { char sym;                /* The main symbol                 */
      WFF  *lsub, *rsub;       /* Pointers to the subformulas     */
    } ;

SBF { int  *mtx,               /* Start of the relevant matrix    */
           *lv, *rv,           /* To values of subformulas        */ 
           val,                /* Currently assigned value        */
           lsb, rsb;           /* Offsets of left and right       */
    } ;

PRM { char h[SZ];              /* Image under homomorphism        */
      PRM *pup;                /* Pointer to the next guy up      */
    } ;

MATRIX { char MC[SZ][SZ],      /* Copy of C matrix found by slave */
              badval[4];       /* Assignments falsifying badguy   */
         MATRIX *nextmat;      /* It's a singly linked list       */
       } ;

JOB { int  axiom[AXMAX],       /* Selected axioms (default none)  */
           adicity[CMAX],      /* Of defined connectives          */
           root[TMAX],         /* Roots of user-defined axioms    */
           defcon[CMAX],       /* Roots of defined connectives    */
           failure,            /* Root of badguy                  */
           atom[2][CMAX],      /* 'a' and 'b' for definitions     */
           logic,              /* The system (default FD)         */
           f_n, f_lat, f_t,
           f_T, f_F, f_fus,    /* The fragment (default all 1)    */
           maxtime,            /* Maximum clock reading           */
           maxmat,             /* Maximum number of good matrices */
           sizmax,             /* Maximum matrix size             */
           sizmax_ismax,       /* (Boolean) Let sizmax float up   */
           totord,             /* Total orders requested          */
           tty_out, fil_out;   /* Output formats                  */
      char outfil_name[80],    /* Text name of output file        */
           logic_name[80],     /* Text name of selected logic     */
           *symbols[3],        /* Actual connectives used         */
           dcs[CMAX+2];        /* Defined connectives (symbols)   */
      WFF  form[FMAX];         /* The (subformulas of) axioms etc */
    } ;



/***
 ***  Now to specify sizeof(unsigned int).
 ***/

#define SUI 32


/***
 ***  The header  string.h  has not been installed on the Sequent,
 ***  so it is necessary to define the one string intrinsic used.
 ***/

char *strchr(s,c)
char *s, c;
{
   while ( *s && *s != c ) s++;
   return( *s? s: 0 );
}


