# This will be the directory for all you source files
SRC_DIR := src

# This will be the directory for all your object files
OBJ_DIR := obj

# This will be the directory for your final executable
BIN_DIR := bin

# The path to your final executable
EXE := $(BIN_DIR)/test_program

# This will contain all of your C files in one string
SRC := $(wildcard $(SRC_DIR)/*.c)

# This function is patsubst('pattern', 'replacement', 'text')
# So we are looking through 'text' finding any matching 'patterns' and then 
# performing a 'replacement'. By the end of this we will have all of our object
# files in one string based off our source files.
OBJ := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))

# Extra flags that you want to give to the C preprocessor and programs that use
# it (the C and Fortran compilers).  The "-MMD, -MP" flags are used to generate
# the header dependencies automatically
CPPFLAGS := -Iinc -MMD -MP

# Extra flags you want to give to the C compiler
CFLAGS   := -Wall

# Extra flags to give to compilers when they are supposed to invoke the linker,
# ‘ld’, such as -L. Libraries (-lfoo) should be added to the LDLIBS variable \
# instead.
LDFLAGS  := -Llib

# Library flags or names given to compilers when they are supposed to invoke 
# the linker, ‘ld’. Non-library linker flags, such as -L, should go in the
# LDFLAGS variable.
LDLIBS   := -lm

# A phony target is one that is not really the name of a file; rather it is 
# just a name for a recipe to be executed when you make an explicit request. 
.PHONY: all clean

# The standard default target for this makefile. It will be the target
# executed when you run 'make' (which is really 'make all')
all: $(EXE)

# ** The all follow the form:
# target: prerequisites ...
# 	recipe

# The target above initiates the next sequence of events below. The following
# target is the linking phase. The "|" is included as a check to make sure the
# $(BIN_DIR) has been created. The "$^" means include all the prerequisites 
# which is the expanded $(OBJ). The "$@" the name of the target which is $(EXE)
$(EXE): $(OBJ) | $(BIN_DIR)
	    $(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

# The target below is the actual compilation to generate object files. The rule
# then says that to generate the .o file, make needs to compile the .c file 
# using the compiler defined in the CC macro. 
# The -c flag says to generate the object file, the -o $@ says to put the output
# of the compilation in the file named on the left side of the ":" while the $<
# is the first item in the dependencies list, and the CFLAGS and CPPFLAGS macros
# are defined as above.
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	    $(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# This target will actually generate the BIN_DIR and OBJ_DIR directories
$(BIN_DIR) $(OBJ_DIR):
	    mkdir -p $@

# This target will be run with "make clean" and will remove the BIN_DIR and 
# OBJ_DIR directories
clean:
	    @$(RM) -rv $(BIN_DIR) $(OBJ_DIR)

# GCC and Clang will create .d files corresponding to your .o files, which 
# contains Makefile rules for us to use, so let's include that in here. The 
# dash is used to silence errors if the files don't exist yet
-include $(OBJ:.o=.d) 

