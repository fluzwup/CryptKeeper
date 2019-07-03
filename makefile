
BASEDIR = .

BINARY = cryptkeeper

CPPSOURCES = main.cpp CryptKeeper.cpp CryptKeeperDES.cpp DES.cpp misc.cpp \
		  CryptKeeperAES.cpp CryptKeeperPW.cpp
CSOURCES = aes256.c

OBJECTS = ${CPPSOURCES:.cpp=.o} ${CSOURCES:.c=.o} 

INCLUDES = -I .  -I /usr/include 

LOCATIONS =  -L/usr/local/lib  -L/usr/lib 

LIBRARIES =  -lcrypto #-lefence
CXXFLAGS = -ggdb  

CXX = g++ ${CXXFLAGS} -DREENTRANT -D_REENTRANT 
CC = gcc ${CXXFLAGS} -DREENTRANT -D_REENTRANT 

.SUFFIXES:      .cpp .o

.cpp.o:
		@echo
		@echo Building $@
		${CXX} ${INCLUDES} -c -o $@ $<          

.c.o:
		@echo
		@echo Building $@
		${CC} ${INCLUDES} -c -o $@ $<          

all:            ${OBJECTS} ${BINARY} 

${BINARY}:      ${OBJECTS}
		@echo
		@echo Building ${BINARY} Executable
		${CXX} -o $@ \
		${OBJECTS}  \
		${LIBRARIES} \
		${LOCATIONS}
                         
clean:
		rm -f ${BINARY} *.o



