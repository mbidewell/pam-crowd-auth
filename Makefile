CC=gcc
CFLAGS=-fPIC -fno-stack-protector -c
OBJ=pam_crowd_auth.o utils.o

LIBS=-lcurl -lpam

.DEFAULT_GOAL := pam_crowd_auth.so

%o : %c
	$(CC) -o lib/$@ $< $(CFLAGS)

%.so: $(OBJ)
	ld -x --shared -o $@ $(OBJ) $(LIBS)

clean:
	rm -f $(OBJ) pam_crowd_auth.so

install: pam_crowd_auth.so
	cp -f pam_crowd_auth.so /usr/lib64/security
	chown root:root /usr/lib64/security/pam_crowd_auth.so
	chmod 0755 /usr/lib64/security/pam_crowd_auth.so
