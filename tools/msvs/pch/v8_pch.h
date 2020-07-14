#include "src/api/api-inl.h"
#include "src/ast/ast.h"
#include "src/builtins/builtins-definitions.h"
#include "src/common/globals.h"
#include "src/heap/base-space.h"
#include "src/heap/cppgc::heap-space.h"
#include "src/heap/heap-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/dictionary-inl.h"
#include "src/objects/js-objects-inl.h"
#include "src/objects/fixed-array-inl.h"
#include "src/utils/utils.h"
#include "src/utils/vector.h"


#include <algorithm>
#include <cstring>
#include <iterator>
#include <iosfwd>
#include <memory>
#include <string>
