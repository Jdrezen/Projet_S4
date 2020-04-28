#include "rsa_header.h"

/// \brief Algorithme de Bézout
/// \file bezout.c
/// \author Mylène Berce
/// \date 22 Janvier 2020
long bezout(uint a,uint b,long *u,long *v){
/// \pre a, b entier naturels
/// \post r entier (naturel) et  u, v entiers relatifs tels que r = pgcd(a, b) et r = a*u+b*v
/// \param[in] : a, b entiers (naturels)
/// \param[out] : u, v entiers relatifs tels que r = pgcd(a, b) et r = a*u+b*v
/// \returns r entier
 	long r = a;
	long rp = b;
	long up = 0;
	long vp = 1;
	long rs,vs,us,q;
  *u=1;
  *v=0;
 	while(rp!=0){
    q=r/rp;
    rs=r;
    us=*u;
    vs=*v;
    r=rp;
    *u=up;
    *v=vp;
    rp=rs-q*rp;
    up=us-q*up;
    vp=vs-q*vp;
  }
	return r;
}

long bezoutRSA(uint a,uint b,long *u,long *v){
  /// \brief récupère (r,u,v) de Bézout. Si u est négatif on le remplace par
  /// \brief le premier qui est supérieur à 2
  long r = bezout(a,b,u,v);
  while (*u<=2){
    *u = *u+b;
  }
  return *u;
}
