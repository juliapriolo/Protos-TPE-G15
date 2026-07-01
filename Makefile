include ./Makefile.inc

SERVER_SOURCES=$(wildcard src/server/*.c)
CLIENT_SOURCES=$(wildcard src/client/*.c)
UTILS_SOURCES=$(wildcard src/utils/*.c)
TEST_SOURCES=$(wildcard tests/*.c)

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
UTILS_OBJECTS=$(UTILS_SOURCES:src/%.c=obj/%.o)
TEST_OBJECTS=$(TEST_SOURCES:tests/%.c=obj/%.o)

OUTPUT_FOLDER=./bin
OBJECTS_FOLDER=./obj

SERVER_OUTPUT_FILE=$(OUTPUT_FOLDER)/server
CLIENT_OUTPUT_FILE=$(OUTPUT_FOLDER)/client
TEST_OUTPUT_FILES=$(TEST_SOURCES:tests/%.c=$(OUTPUT_FOLDER)/%)

ifeq ($(strip $(CLIENT_SOURCES)),)
ALL_TARGETS=server
else
ALL_TARGETS=server client
endif

all: $(ALL_TARGETS)
server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)
tests: $(TEST_OUTPUT_FILES)

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(UTILS_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $(SERVER_OBJECTS) $(UTILS_OBJECTS) -o $(SERVER_OUTPUT_FILE)

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(UTILS_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $(CLIENT_OBJECTS) $(UTILS_OBJECTS) -o $(CLIENT_OUTPUT_FILE)

$(OUTPUT_FOLDER)/%: obj/%.o $(UTILS_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $(LD_FLAGS) $< $(UTILS_OBJECTS) -o $@

obj/%.o: src/%.c
	mkdir -p $(OBJECTS_FOLDER)/server
	mkdir -p $(OBJECTS_FOLDER)/client
	mkdir -p $(OBJECTS_FOLDER)/utils
	$(COMPILER) $(COMPILER_FLAGS) -c $< -o $@

obj/%.o: tests/%.c
	mkdir -p $(OBJECTS_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -c $< -o $@

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

.PHONY: all server client tests clean
