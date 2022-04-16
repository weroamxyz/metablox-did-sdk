#CC=g++ -std=c99
CC=g++ 
#-std=c++11
# -fpermissive
#-lstdc++
VPATH=..
#VPATH:=/home/meiqiu/did/did_sdk-main
DID_DIR=$(VPATH)/did
DID_KEY=$(VPATH)/did_key
DID_WALLET=$(VPATH)/did_wallet
DID_DESISTER=$(VPATH)/did_register
DID_CONF=$(VPATH)/conf
DID_COMMON=$(VPATH)/common
DID_DEMO=$(VPATH)/did_demo/did_demo
DID_JSON=$(VPATH)/cJSON
DID_LIB=$(VPATH)/lib

LDFLAGS := -L$(DID_LIB)
LIBS    := libcrul.a libsecp256k1.a

#SRCS=$(wildcard ../../common/*.c)
SRCS = $(wildcard $(DID_COMMON)/*.c $(DID_WALLET)/*.c $(DID_DIR)/*.c $(DID_JSON)/*.c $(DID_DESISTER)/*.c $(DID_KEY)/*.c $(DID_KEY)/secp256k1/*.c $(DID_DEMO)/*.c $(DID_KEY)/secp256k1/*.c)

OBJS=$(patsubst %c, %o, $(SRCS))

#$(warning $(SRCS))

TARGET=main

INCLUDES := -I$(VPATH) -I$(VPATH)/did -I$(VPATH)/did_key -I$(VPATH)/did_key/secp256k1 -I$(VPATH)/third-party -I$(VPATH)/third-party/curl -I$(VPATH)/third-party/curl/include -I$(VPATH)/third-party/curl/include/curl -I$(VPATH)/third-party/leveldb -I$(VPATH)/third-party/leveldb/include -I$(VPATH)/third-party/leveldb/include/leveldb

#INCLUDES := -I$(VPATH) -I$(VPATH)/did -I$(VPATH)/common -I$(VPATH)/lib -I$(VPATH)/third-party/leveldb/include/leveldb 
#-I$(VPATH)/curl/build/lib -I/home/meiqiu/did/did_sdk-main/third-party/leveldb/build -I/usr/lib


.PHONY:all

all:$(TARGET)

$(TARGET):$(OBJS)
	        $(CC) $(INCLUDES) $^ -std=c++11 -lsecp256k1 -lleveldb -lcurl -lpthread -L$(DID_LIB) -o $@ 
#$(CC) $(INCLUDES) -o $@ $^ 
#-lsecp256k1 -lleveldb -lcurl -pthread -L$(DID_LIB)
#-L./usr/lib64

#-lpthread libsecp256k1.a libleveldb.a libcurl.so
#-Xlinker "-(" -lpthread -lsecp256k1 -lleveldb -lcurl -Xlinker "-)" 

%.o:%.c
	        $(CC) $(INCLUDES) -fpermissive  -c  $< -o $@
.PHONY:clean
clean:
	-rm -f $(OBJS) $(TARGET)


