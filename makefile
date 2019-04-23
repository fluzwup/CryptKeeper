
BASEDIR = .

BINARY = cryptkeeper

SOURCES = main.cpp CryptKeeper.cpp CryptKeeperDES.cpp DES.cpp misc.cpp \
		  CryptKeeperAES.cpp aes256.c

OBJECTS = ${SOURCES:.cpp=.o} 

INCLUDES = -I .  -I /usr/include 

LOCATIONS =  -L/usr/local/lib  -L/usr/lib 

LIBRARIES =  
CXXFLAGS = -O2  -D_NDEBUG

CXX = g++ ${CXXFLAGS} -DREENTRANT -D_REENTRANT 

.SUFFIXES:      .cpp .o

.cpp.o:
		@echo
		@echo Building $@
		${CXX} ${INCLUDES} -c -o $@ $<          

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



