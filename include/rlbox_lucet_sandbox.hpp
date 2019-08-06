#pragma once

#include "lucet_sandbox.h"
#include <cstdint>
#include <iostream>
#include <limits>
#include <type_traits>
#include <utility>
#include <vector>

#define RLBOX_LUCET_UNUSED(...) (void)__VA_ARGS__

namespace rlbox {

namespace lucet_detail {

template <typename T> constexpr bool false_v = false;

// https://stackoverflow.com/questions/6512019/can-we-get-the-type-of-a-lambda-argument
namespace return_argument_detail {
template <typename Ret, typename... Rest> Ret helper(Ret (*)(Rest...));

template <typename Ret, typename F, typename... Rest>
Ret helper(Ret (F::*)(Rest...));

template <typename Ret, typename F, typename... Rest>
Ret helper(Ret (F::*)(Rest...) const);

template <typename F> decltype(helper(&F::operator())) helper(F);
} // namespace return_argument_detail

template <typename T>
using return_argument =
    decltype(return_argument_detail::helper(std::declval<T>()));

///////////////////////////////////////////////////////////////

template <typename T, typename = void> struct convert_type_to_wasm_type {
  static_assert(std::is_void_v<T>, "Missing specialization");
  using type = void;
  static constexpr enum LucetValueType lucet_type = LucetValueType_Void;
};

template <typename T>
struct convert_type_to_wasm_type<
    T, std::enable_if_t<(std::is_integral_v<T> ||
                         std::is_enum_v<T>)&&sizeof(T) <= sizeof(uint32_t)>> {
  using type = uint32_t;
  static constexpr enum LucetValueType lucet_type = LucetValueType_I32;
};

template <typename T>
struct convert_type_to_wasm_type<
    T, std::enable_if_t<(std::is_integral_v<T> ||
                         std::is_enum_v<T>)&&sizeof(uint32_t) < sizeof(T) &&
                        sizeof(T) <= sizeof(uint64_t)>> {
  using type = uint64_t;
  static constexpr enum LucetValueType lucet_type = LucetValueType_I64;
};

template <typename T>
struct convert_type_to_wasm_type<T,
                                 std::enable_if_t<std::is_same_v<T, float>>> {
  using type = T;
  static constexpr enum LucetValueType lucet_type = LucetValueType_F32;
};

template <typename T>
struct convert_type_to_wasm_type<T,
                                 std::enable_if_t<std::is_same_v<T, double>>> {
  using type = T;
  static constexpr enum LucetValueType lucet_type = LucetValueType_F64;
};

template <typename T>
struct convert_type_to_wasm_type<
    T, std::enable_if_t<std::is_pointer_v<T> || std::is_class_v<T>>> {
  // pointers are 32 bit indexes in wasm
  // class paramters are passed as a pointer to an object in the stack or heap
  using type = uint32_t;
  static constexpr enum LucetValueType lucet_type = LucetValueType_I32;
};

} // namespace lucet_detail

class rlbox_lucet_sandbox {
public:
  using T_LongLongType = int32_t;
  using T_LongType = int32_t;
  using T_IntType = int32_t;
  using T_PointerType = uint32_t;
  using T_ShortType = int16_t;

private:
  LucetSandboxInstance *sandbox = nullptr;
  void *malloc_index = 0;
  void *free_index = 0;

  void dynamic_check(bool success, const char *error_message) {
    if (!success) {
      std::cout << error_message << "\n";
      abort();
    }
  }

  template <typename T_Formal, typename T_Actual>
  inline LucetValue serialize_arg(std::vector<T_PointerType> &allocations,
                                  T_Actual arg) {
    LucetValue ret;
    using T = T_Formal;
    if constexpr ((std::is_integral_v<T> || std::is_enum_v<T>)&&sizeof(T) <=
                  sizeof(uint32_t)) {
      static_assert(lucet_detail::convert_type_to_wasm_type<T>::lucet_type ==
                    LucetValueType_I32);
      ret.val_type = LucetValueType_I32;
      ret.u32 = static_cast<uint32_t>(arg);
    } else if constexpr ((std::is_integral_v<T> ||
                          std::is_enum_v<T>)&&sizeof(T) <= sizeof(uint64_t)) {
      static_assert(lucet_detail::convert_type_to_wasm_type<T>::lucet_type ==
                    LucetValueType_I64);
      ret.val_type = LucetValueType_I64;
      ret.u64 = static_cast<uint64_t>(arg);
    } else if constexpr (std::is_same_v<T, float>) {
      static_assert(lucet_detail::convert_type_to_wasm_type<T>::lucet_type ==
                    LucetValueType_F32);
      ret.val_type = LucetValueType_F32;
      ret.f32 = arg;
    } else if constexpr (std::is_same_v<T, double>) {
      static_assert(lucet_detail::convert_type_to_wasm_type<T>::lucet_type ==
                    LucetValueType_F64);
      ret.val_type = LucetValueType_F64;
      ret.f64 = arg;
    } else if constexpr (std::is_class_v<T>) {
      auto sandboxed_ptr = this->impl_malloc_in_sandbox(sizeof(T));
      allocations.push_back(sandboxed_ptr);
      auto ptr = reinterpret_cast<T *>(
          this->impl_get_unsandboxed_pointer<T>(sandboxed_ptr));
      *ptr = arg;

      // sanity check that pointers are stored as i32s
      static_assert(lucet_detail::convert_type_to_wasm_type<T *>::lucet_type ==
                    LucetValueType_I32);
      ret.val_type = LucetValueType_I32;
      ret.u32 = sandboxed_ptr;
    } else {
      static_assert(lucet_detail::false_v<T>,
                    "Unexpected case for serialize_arg");
    }
    return ret;
  }

  template <typename T_Ret, typename... T_FormalArgs, typename... T_ActualArgs>
  inline void serialize_args(std::vector<T_PointerType> & /* allocations */,
                             LucetValue * /* out_lucet_args */,
                             T_Ret (*/* func_ptr */)(T_FormalArgs...),
                             T_ActualArgs... /* args */) {
    static_assert(sizeof...(T_FormalArgs) == 0);
    static_assert(sizeof...(T_ActualArgs) == 0);
  }

  template <typename T_Ret, typename T_FormalArg, typename... T_FormalArgs,
            typename T_ActualArg, typename... T_ActualArgs>
  inline void serialize_args(std::vector<T_PointerType> &allocations,
                             LucetValue *out_lucet_args,
                             T_Ret (*func_ptr)(T_FormalArg, T_FormalArgs...),
                             T_ActualArg arg, T_ActualArgs... args) {
    RLBOX_LUCET_UNUSED(func_ptr);
    *out_lucet_args = serialize_arg<T_FormalArg>(allocations, arg);
    out_lucet_args++;

    using T_Curried = T_Ret (*)(T_FormalArgs...);
    T_Curried curried_func_ptr = nullptr;

    serialize_args(allocations, out_lucet_args, curried_func_ptr,
                   std::forward<T_ActualArgs>(args)...);
  }

  template <typename T_Ret, typename... T_FormalArgs, typename... T_ActualArgs>
  inline size_t serialize_return_and_args(
      std::vector<T_PointerType> &allocations, LucetValue *out_lucet_args,
      T_Ret (*func_ptr)(T_FormalArgs...), T_ActualArgs &&... args) {

    size_t ret = sizeof...(T_FormalArgs);
    if constexpr (std::is_class_v<T_Ret>) {
      auto sandboxed_ptr = this->impl_malloc_in_sandbox(sizeof(T_Ret));
      allocations.push_back(sandboxed_ptr);

      // sanity check that pointers are stored as i32s
      static_assert(
          lucet_detail::convert_type_to_wasm_type<T_Ret *>::lucet_type ==
          LucetValueType_I32);
      out_lucet_args->val_type = LucetValueType_I32;
      out_lucet_args->u32 = sandboxed_ptr;
      out_lucet_args++;
      ret++;
    }

    serialize_args(allocations, out_lucet_args, func_ptr,
                   std::forward<T_ActualArgs>(args)...);
    return ret;
  }

  template <typename T_FormalRet, typename T_ActualRet>
  inline auto serialize_return_value(T_ActualRet arg) {
    if constexpr (std::is_class_v<T_FormalRet>) {
      // structs returned as pointers into wasm memory/wasm stack
      auto ptr = reinterpret_cast<T_FormalRet *>(
          impl_get_unsandboxed_pointer<T_FormalRet *>(arg));
      T_FormalRet ret = *ptr;
      return ret;
    } else {
      return arg;
    }
  }

protected:
  inline void impl_create_sandbox(const char *lucet_module_path) {
    dynamic_check(sandbox == nullptr, "Sandbox already initialized");
    sandbox = lucet_load_module(lucet_module_path);
    dynamic_check(sandbox != nullptr, "Sandbox could not be created");

    auto heap_base = reinterpret_cast<uintptr_t>(lucet_get_heap_base(sandbox));
    // Check that the address space is larger than the sandbox heap i.e. 4GB
    // sandbox heap, host has to have more than 4GB
    static_assert(sizeof(uintptr_t) > sizeof(T_PointerType));
    // Check that the heap is aligned to the pointer size i.e. 32-bit pointer =>
    // aligned to 4GB. The implementations of
    // impl_get_unsandboxed_pointer_no_ctx and impl_get_sandboxed_pointer_no_ctx
    // below rely on this.
    uintptr_t heap_offset_mask = std::numeric_limits<T_PointerType>::max();
    dynamic_check((heap_base & heap_offset_mask) == 0,
                  "Sandbox heap not aligned to 4GB");

    // cache these for performance
    malloc_index = impl_lookup_symbol("malloc");
    free_index = impl_lookup_symbol("free");
  }

  inline void impl_destroy_sandbox() { lucet_drop_module(sandbox); }

  template <typename T>
  inline void *impl_get_unsandboxed_pointer(T_PointerType p) const {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      std::abort();
    } else {
      return lucet_get_unsandboxed_ptr(sandbox, static_cast<uintptr_t>(p));
    }
  }

  template <typename T>
  inline T_PointerType impl_get_sandboxed_pointer(const void *p) const {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      std::abort();
    } else {
      return static_cast<T_PointerType>(
          lucet_get_sandboxed_ptr(sandbox, const_cast<void *>(p)));
    }
  }

  template <typename T>
  static inline void *
  impl_get_unsandboxed_pointer_no_ctx(T_PointerType p,
                                      const void *example_unsandboxed_ptr) {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      static_assert(lucet_detail::false_v<T>,
                    "No context swizzling for a function pointer.");
    } else {
      // grab the memory base from the example_unsandboxed_ptr
      uintptr_t heap_base_mask = std::numeric_limits<uintptr_t>::max() &
                                 ~(static_cast<uintptr_t>(std::numeric_limits<T_PointerType>::max()));
      uintptr_t heap_base =
          reinterpret_cast<uintptr_t>(example_unsandboxed_ptr) & heap_base_mask;
      uintptr_t ret = heap_base | p;
      return reinterpret_cast<void *>(ret);
    }
  }

  template <typename T>
  static inline T_PointerType impl_get_sandboxed_pointer_no_ctx(
      const void *p, const void * /* example_unsandboxed_ptr */) {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      static_assert(lucet_detail::false_v<T>,
                    "No context swizzling for a function pointer.");
    } else {
      // Just clear the memory base to leave the offset
      uintptr_t ret = reinterpret_cast<uintptr_t>(p) &
                      std::numeric_limits<T_PointerType>::max();
      return static_cast<T_PointerType>(ret);
    }
  }

  static inline bool impl_is_in_same_sandbox(const void *p1, const void *p2) {
    uintptr_t heap_base_mask = std::numeric_limits<uintptr_t>::max() &
                               ~(std::numeric_limits<T_PointerType>::max());
    return (reinterpret_cast<uintptr_t>(p1) & heap_base_mask) ==
           (reinterpret_cast<uintptr_t>(p2) & heap_base_mask);
  }

  inline bool impl_is_pointer_in_sandbox_memory(const void *p) {
    auto heap_base = reinterpret_cast<uintptr_t>(impl_get_memory_location());
    size_t length = impl_get_total_memory();
    uintptr_t p_val = reinterpret_cast<uintptr_t>(p);
    return p_val >= heap_base && p_val < (heap_base + length);
  }

  inline bool impl_is_pointer_in_app_memory(const void *p) {
    return !(impl_is_pointer_in_sandbox_memory(p));
  }

  inline size_t impl_get_total_memory() { return lucet_get_heap_size(sandbox); }

  inline void *impl_get_memory_location() {
    return lucet_get_heap_base(sandbox);
  }

  void *impl_lookup_symbol(const char *func_name) {
    // just use the string itself as lucet does its own symbol resolution
    return const_cast<void *>(reinterpret_cast<const void *>(func_name));
  }

  template <typename T, typename T_Converted, typename... T_Args>
  auto impl_invoke_with_func_ptr(T_Converted *func_ptr, T_Args &&... params) {
    const char *func_name = reinterpret_cast<const char *>(func_ptr);
    std::vector<T_PointerType> allocations;
    // Add one as the return value may require an arg slot for structs
    LucetValue args[1 + sizeof...(params)];
    size_t arg_length = serialize_return_and_args(
        allocations, &(args[0]), func_ptr, std::forward<T_Args>(params)...);

    using T_Ret = lucet_detail::return_argument<T_Converted>;
    // struct returns are returned as pointers
    using T_Wasm_Ret = typename lucet_detail::convert_type_to_wasm_type<T_Ret>::type;

    if constexpr (std::is_void_v<T_Wasm_Ret>) {
      lucet_run_function_return_void(sandbox, func_name, arg_length,
                                     &(args[0]));
      for (auto ptr : allocations) {
        impl_free_in_sandbox(ptr);
      }
      return;
    } else {

      T_Wasm_Ret ret;
      if constexpr (std::is_same_v<T_Wasm_Ret, uint32_t>) {
        ret = lucet_run_function_return_u32(sandbox, func_name, arg_length,
                                            &(args[0]));
      } else if constexpr (std::is_same_v<T_Wasm_Ret, uint64_t>) {
        ret = lucet_run_function_return_u64(sandbox, func_name, arg_length,
                                            &(args[0]));
      } else if constexpr (std::is_same_v<T_Wasm_Ret, float>) {
        ret = lucet_run_function_return_f32(sandbox, func_name, arg_length,
                                            &(args[0]));
      } else if constexpr (std::is_same_v<T_Wasm_Ret, double>) {
        ret = lucet_run_function_return_f64(sandbox, func_name, arg_length,
                                            &(args[0]));
      } else {
        static_assert(lucet_detail::false_v<T_Wasm_Ret>, "Unknown invoke return type");
      }

      auto serialized_ret = serialize_return_value<T_Ret>(ret);
      // free only after serializing return, as return values such as structs
      // are returned as pointers which we must free
      for (auto ptr : allocations) {
        impl_free_in_sandbox(ptr);
      }
      return serialized_ret;
    }
  }

  inline T_PointerType impl_malloc_in_sandbox(size_t size) {
    dynamic_check(size <= std::numeric_limits<uint32_t>::max(),
                  "Attempting to malloc more than the heap size");
    using T_Func = void *(size_t);
    using T_Converted = T_PointerType(uint32_t);
    T_PointerType ret = impl_invoke_with_func_ptr<T_Func, T_Converted>(
        reinterpret_cast<T_Converted *>(malloc_index),
        static_cast<uint32_t>(size));
    return ret;
  }

  inline void impl_free_in_sandbox(T_PointerType p) {
    using T_Func = void(void *);
    using T_Converted = void(T_PointerType);
    impl_invoke_with_func_ptr<T_Func, T_Converted>(
        reinterpret_cast<T_Converted *>(free_index), p);
  }

  template <typename T_Ret, typename... T_Args>
  inline T_PointerType impl_register_callback(void *key, void *callback) {
    RLBOX_LUCET_UNUSED(key);
    RLBOX_LUCET_UNUSED(callback);
    std::abort();
  }

  static inline std::pair<rlbox_lucet_sandbox *, void *>
  impl_get_executed_callback_sandbox_and_key() {
    std::abort();
  }

  template <typename T_Ret, typename... T_Args>
  inline void impl_unregister_callback(void *key) {
    RLBOX_LUCET_UNUSED(key);
    std::abort();
  }
};

} // namespace rlbox