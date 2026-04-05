CXXFLAGS += -Wall -Wextra -std=c++20 -fPIC -I ../../include -I ../../helpers

OS_NAME := $(shell uname | tr '[:upper:]' '[:lower:]')

ifeq ($(OS_NAME),darwin)
    JAVA_HOME ?= $(shell /usr/libexec/java_home)
else
    JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(which javac))))
endif

CXXFLAGS += -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/$(OS_NAME)

# LIB_DIR is passed as a compile-time string so module.cpp can find the JARs
# at runtime via jvmloader (same pattern as the bitcoinj and eclair modules).
LIB_DIR = $(shell pwd)/lib
CXXFLAGS += -DLIB_DIR=\"$(LIB_DIR)\"

BUILD_DIR = app/build/distributions

all: module.a

# Unpack the Gradle distribution zip and collect all dependency JARs into lib/
lib: $(BUILD_DIR)/app.zip
	mkdir -p lib
	mkdir -p bitcoins_extracted
	unzip -o $(BUILD_DIR)/app.zip -d bitcoins_extracted
	cp -r bitcoins_extracted/*/lib/* lib/
	rm -rf bitcoins_extracted

# Build the Gradle project; the `application` plugin produces a zip containing
# the Wrapper class together with bitcoin-s and the Scala runtime.
$(BUILD_DIR)/app.zip:
	./gradlew build

# Compile the plain-Java wrapper and bundle it as BitcoinSWrapper.jar so it
# lands on the JVM classpath at runtime (same pattern as EclairWrapper.jar).
lib/BitcoinSWrapper.jar: lib
	javac -cp ".:lib/*" BitcoinSWrapper.java
	jar cf BitcoinSWrapper.jar BitcoinSWrapper.class
	mv BitcoinSWrapper.jar lib/BitcoinSWrapper.jar

module.a: lib module.o lib/BitcoinSWrapper.jar
	$(AR) rcs $@ module.o
	ranlib $@

module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o

format:
	clang-format -i module.h module.cpp

check-format:
	clang-format -Werror --fail-on-incomplete-format -n module.h module.cpp

clean:
	rm -f *.o *.a
	rm -rf lib bitcoins_extracted
	./gradlew clean 2>/dev/null || true

.PHONY: all lib clean format check-format $(BUILD_DIR)/app.zip
