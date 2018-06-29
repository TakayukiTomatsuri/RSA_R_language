install.packages("gmp")
library("gmp")

# 10進数でasciiコードと文字を変換する(10進数)
# https://www.r-bloggers.com/ascii-code-table-in-r/
asc <- function(x) { strtoi(charToRaw(x),16L) }
chr <- function(n) { rawToChar(as.raw(n)) }

#拡張ユークリッド、引数にax+by = c の a,bを与える
## 戻り値は(c,x,y)
extended_euclidean <- function(a, b){
  if(a == 0){
    return(list(c=b, x=0, y=1))
  }else{
    res = extended_euclidean(b%%a, a)
    tg = res[["c"]]
    tx = res[["x"]]
    ty = res[["y"]]
    return(list(c=tg, x=(ty-(b%/%a)*tx), y=tx))
  }
}

generate_keys <- function(p, q){
  # N(公開鍵)
  N <- as.integer(p*q)
  # φ(p,q)
  L <- as.integer((p-1)*(q-1))
  
  # D*E = 1 (mod φ(p,q) )を満たすEを探し公開鍵とする(E=65537にしとくのが無難だけど)
  for (i in 2:L) {
    if( gcd(i, L) == 1){
      E <- as.integer(i)
      break
    }
  }
  
  # φ(p,q) を法としたときの、Eの逆元を求めてそれをD(秘密鍵)とする
  # https://www.mew.org/~kazu/doc/rsa.html
  res = extended_euclidean(L, E)
  D = res[["y"]]
  
  return( list(public_key=list(E=E,N=N) , private_key=list(D=D,N=N)))
}

decrypt <- function(cypher_text, private_key=list(D=0, N=0)){
  D <- as.integer(private_key['D'])
  N <- as.integer(private_key['N'])
  
  decrypted_list = list()
  for(ctext in cypher_text){
    ans <- 1
    #普通に累乗してからNの剰余を計算すると大きすぎてオーバーフローするので、1回1回掛けながらその度に剰余を計算する
    for (i in 1:D) {
      ans <- (ans * ctext) %% N
    }
    decrypted_list = c(decrypted_list, list(chr(ans)) )
  }
  return(paste(decrypted_list, collapse=""))
}

encrypt <- function(plain_text, public_key=list(E=0, N=0)){
  plain_text_num = asc(plain_text)
  E <- as.integer(public_key['E'])
  N <- as.integer(public_key['N'])
  
  encrpted_list = list()
  for(ptext in plain_text_num){
    ans <- 1
    for (i in 1:E) {
      ans <- (ans * ptext) %% N
    }
    encrpted_list = c(encrpted_list, list(ans))
  }
  
  return(encrpted_list )
}

#使用例-------------------s
# p=43, q=53として鍵生成
keys = generate_keys(43, 53)
# 12zz を暗号化
cyper_text <- encrypt("12zz", keys[['public_key']])
# 複合すると元の12zzになる
decrypted_text <- decrypt(cyper_text, keys[['private_key']])
decrypted_text

