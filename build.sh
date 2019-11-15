gcc -fPIC -fno-stack-protector -c pam_crowd_auth.c -o auth.o
ld -x --shared -o /usr/lib64/security/pam_crowd_auth.so auth.o -l curl
