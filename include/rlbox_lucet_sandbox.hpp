#pragma once

#include "lucet_sandbox.h"

#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
// RLBox allows applications to provide a custom shared lock implementation
#ifndef rlbox_use_custom_shared_lock
#  include <shared_mutex>
#endif
#include <type_traits>
#include <utility>

#define RLBOX_LUCET_UNUSED(...) (void)__VA_ARGS__

// Use the same convention as rlbox to allow applications to customize the
// shared lock
#ifndef rlbox_use_custom_shared_lock
#  define rlbox_shared_lock(name) std::shared_timed_mutex name
#  define rlbox_acquire_shared_guard(name, ...)                                \
    std::shared_lock<std::shared_timed_mutex> name(__VA_ARGS__)
#  define rlbox_acquire_unique_guard(name, ...)                                \
    std::unique_lock<std::shared_timed_mutex> name(__VA_ARGS__)
#else
#  if !defined(rlbox_shared_lock) || !defined(rlbox_acquire_shared_guard) ||   \
    !defined(rlbox_acquire_unique_guard)
#    error                                                                     \
      "rlbox_use_custom_shared_lock defined but missing definitions for rlbox_shared_lock, rlbox_acquire_shared_guard, rlbox_acquire_unique_guard"
#  endif
#endif

namespace rlbox {

namespace detail {
  // relying on the dynamic check settings (exception vs abort) in the rlbox lib
  inline void dynamic_check(bool check, const char* const msg);
}

namespace lucet_detail {

  template<typename T>
  constexpr bool false_v = false;

  // https://stackoverflow.com/questions/6512019/can-we-get-the-type-of-a-lambda-argument
  namespace return_argument_detail {
    template<typename Ret, typename... Rest>
    Ret helper(Ret (*)(Rest...));

    template<typename Ret, typename F, typename... Rest>
    Ret helper(Ret (F::*)(Rest...));

    template<typename Ret, typename F, typename... Rest>
    Ret helper(Ret (F::*)(Rest...) const);

    template<typename F>
    decltype(helper(&F::operator())) helper(F);
  } // namespace return_argument_detail

  template<typename T>
  using return_argument =
    decltype(return_argument_detail::helper(std::declval<T>()));

  ///////////////////////////////////////////////////////////////

  // https://stackoverflow.com/questions/37602057/why-isnt-a-for-loop-a-compile-time-expression
  namespace compile_time_for_detail {
    template<std::size_t N>
    struct num
    {
      static const constexpr auto value = N;
    };

    template<class F, std::size_t... Is>
    inline void compile_time_for_helper(F func, std::index_sequence<Is...>)
    {
      (func(num<Is>{}), ...);
    }
  } // namespace compile_time_for_detail

  template<std::size_t N, typename F>
  inline void compile_time_for(F func)
  {
    compile_time_for_detail::compile_time_for_helper(
      func, std::make_index_sequence<N>());
  }

  ///////////////////////////////////////////////////////////////

  template<typename T, typename = void>
  struct convert_type_to_wasm_type
  {
    static_assert(std::is_void_v<T>, "Missing specialization");
    using type = void;
    static constexpr enum LucetValueType lucet_type = LucetValueType_Void;
  };

  template<typename T>
  struct convert_type_to_wasm_type<
    T,
    std::enable_if_t<(std::is_integral_v<T> || std::is_enum_v<T>)&&sizeof(T) <=
                     sizeof(uint32_t)>>
  {
    using type = uint32_t;
    static constexpr enum LucetValueType lucet_type = LucetValueType_I32;
  };

  template<typename T>
  struct convert_type_to_wasm_type<
    T,
    std::enable_if_t<(std::is_integral_v<T> ||
                      std::is_enum_v<T>)&&sizeof(uint32_t) < sizeof(T) &&
                     sizeof(T) <= sizeof(uint64_t)>>
  {
    using type = uint64_t;
    static constexpr enum LucetValueType lucet_type = LucetValueType_I64;
  };

  template<typename T>
  struct convert_type_to_wasm_type<T,
                                   std::enable_if_t<std::is_same_v<T, float>>>
  {
    using type = T;
    static constexpr enum LucetValueType lucet_type = LucetValueType_F32;
  };

  template<typename T>
  struct convert_type_to_wasm_type<T,
                                   std::enable_if_t<std::is_same_v<T, double>>>
  {
    using type = T;
    static constexpr enum LucetValueType lucet_type = LucetValueType_F64;
  };

  template<typename T>
  struct convert_type_to_wasm_type<
    T,
    std::enable_if_t<std::is_pointer_v<T> || std::is_class_v<T>>>
  {
    // pointers are 32 bit indexes in wasm
    // class paramters are passed as a pointer to an object in the stack or heap
    using type = uint32_t;
    static constexpr enum LucetValueType lucet_type = LucetValueType_I32;
  };

} // namespace lucet_detail

class rlbox_lucet_sandbox
{
public:
  using T_LongLongType = int32_t;
  using T_LongType = int32_t;
  using T_IntType = int32_t;
  using T_PointerType = uint32_t;
  using T_ShortType = int16_t;

private:
  LucetSandboxInstance* sandbox = nullptr;
  uintptr_t heap_base;
  void* malloc_index = 0;
  void* free_index = 0;

  static const size_t MAX_CALLBACKS = 128;
  rlbox_shared_lock(callback_mutex);
  void* callback_unique_keys[MAX_CALLBACKS]{ 0 };
  void* callbacks[MAX_CALLBACKS]{ 0 };
  uint32_t callback_slot_assignment[MAX_CALLBACKS]{ 0 };

  using TableElementRef = LucetFunctionTableElement*;
  struct FunctionTable
  {
    TableElementRef elements[MAX_CALLBACKS];
    uint32_t slot_number[MAX_CALLBACKS];
  };
  inline static std::mutex callback_table_mutex;
  inline static std::map<void*, std::weak_ptr<FunctionTable>>
    shared_callback_slots;
  std::shared_ptr<FunctionTable> callback_slots = nullptr;

  struct rlbox_lucet_sandbox_thread_local
  {
    rlbox_lucet_sandbox* sandbox;
    uint32_t last_callback_invoked;
  };

  thread_local static inline rlbox_lucet_sandbox_thread_local thread_data{ 0,
                                                                           0 };

  template<typename T_Formal, typename T_Actual>
  inline LucetValue serialize_arg(T_PointerType* allocations, T_Actual arg)
  {
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
      *allocations = sandboxed_ptr;
      allocations++;

      auto ptr = reinterpret_cast<T*>(
        this->impl_get_unsandboxed_pointer<T>(sandboxed_ptr));
      *ptr = arg;

      // sanity check that pointers are stored as i32s
      static_assert(lucet_detail::convert_type_to_wasm_type<T*>::lucet_type ==
                    LucetValueType_I32);
      ret.val_type = LucetValueType_I32;
      ret.u32 = sandboxed_ptr;
    } else {
      static_assert(lucet_detail::false_v<T>,
                    "Unexpected case for serialize_arg");
    }
    return ret;
  }

  template<typename T_Ret, typename... T_FormalArgs, typename... T_ActualArgs>
  inline void serialize_args(T_PointerType* /* allocations */,
                             LucetValue* /* out_lucet_args */,
                             T_Ret (*/* func_ptr */)(T_FormalArgs...),
                             T_ActualArgs... /* args */)
  {
    static_assert(sizeof...(T_FormalArgs) == 0);
    static_assert(sizeof...(T_ActualArgs) == 0);
  }

  template<typename T_Ret,
           typename T_FormalArg,
           typename... T_FormalArgs,
           typename T_ActualArg,
           typename... T_ActualArgs>
  inline void serialize_args(T_PointerType* allocations,
                             LucetValue* out_lucet_args,
                             T_Ret (*func_ptr)(T_FormalArg, T_FormalArgs...),
                             T_ActualArg arg,
                             T_ActualArgs... args)
  {
    RLBOX_LUCET_UNUSED(func_ptr);
    *out_lucet_args = serialize_arg<T_FormalArg>(allocations, arg);
    out_lucet_args++;

    using T_Curried = T_Ret (*)(T_FormalArgs...);
    T_Curried curried_func_ptr = nullptr;

    serialize_args(allocations,
                   out_lucet_args,
                   curried_func_ptr,
                   std::forward<T_ActualArgs>(args)...);
  }

  template<typename T_Ret, typename... T_FormalArgs, typename... T_ActualArgs>
  inline void serialize_return_and_args(T_PointerType* allocations,
                                        LucetValue* out_lucet_args,
                                        T_Ret (*func_ptr)(T_FormalArgs...),
                                        T_ActualArgs&&... args)
  {

    if constexpr (std::is_class_v<T_Ret>) {
      auto sandboxed_ptr = this->impl_malloc_in_sandbox(sizeof(T_Ret));
      *allocations = sandboxed_ptr;
      allocations++;

      // sanity check that pointers are stored as i32s
      static_assert(
        lucet_detail::convert_type_to_wasm_type<T_Ret*>::lucet_type ==
        LucetValueType_I32);
      out_lucet_args->val_type = LucetValueType_I32;
      out_lucet_args->u32 = sandboxed_ptr;
      out_lucet_args++;
    }

    serialize_args(allocations,
                   out_lucet_args,
                   func_ptr,
                   std::forward<T_ActualArgs>(args)...);
  }

  template<typename T_FormalRet, typename T_ActualRet>
  inline auto serialize_to_sandbox(T_ActualRet arg)
  {
    if constexpr (std::is_class_v<T_FormalRet>) {
      // structs returned as pointers into wasm memory/wasm stack
      auto ptr = reinterpret_cast<T_FormalRet*>(
        impl_get_unsandboxed_pointer<T_FormalRet*>(arg));
      T_FormalRet ret = *ptr;
      return ret;
    } else {
      return arg;
    }
  }

  inline void set_callbacks_slots_ref()
  {
    LucetFunctionTable functionPointerTable =
      lucet_get_function_pointer_table(sandbox);
    void* key = functionPointerTable.data;

    std::lock_guard<std::mutex> lock(callback_table_mutex);
    std::weak_ptr<FunctionTable> slots = shared_callback_slots[key];

    if (auto shared_slots = slots.lock()) {
      // pointer exists
      callback_slots = shared_slots;
      return;
    }

    callback_slots = std::make_shared<FunctionTable>();

    for (size_t i = 0; i < MAX_CALLBACKS; i++) {
      uintptr_t reservedVal =
        lucet_get_reserved_callback_slot_val(sandbox, i + 1);

      for (size_t j = 0; j < functionPointerTable.length; j++) {
        if (functionPointerTable.data[j].rf == reservedVal) {
          functionPointerTable.data[j].rf = 0;
          callback_slots->elements[i] = &(functionPointerTable.data[j]);
          callback_slots->slot_number[i] = static_cast<uint32_t>(j);
          break;
        }
      }
    }

    shared_callback_slots[key] = callback_slots;
  }

  template<uint32_t N, typename T_Ret, typename... T_Args>
  static typename lucet_detail::convert_type_to_wasm_type<T_Ret>::type
  callback_interceptor(
    void* /* vmContext */,
    typename lucet_detail::convert_type_to_wasm_type<T_Args>::type... params)
  {
    thread_data.last_callback_invoked = N;
    using T_Func = T_Ret (*)(T_Args...);
    T_Func func;
    {
      rlbox_acquire_shared_guard(lock, thread_data.sandbox->callback_mutex);
      func = reinterpret_cast<T_Func>(thread_data.sandbox->callbacks[N]);
    }
    // Callbacks are invoked through function pointers, cannot use std::forward
    // as we don't have caller context for T_Args, which means they are all
    // effectively passed by value
    return func(thread_data.sandbox->serialize_to_sandbox<T_Args>(params)...);
  }

  template<uint32_t N, typename T_Ret, typename... T_Args>
  static void callback_interceptor_promoted(
    void* /* vmContext */,
    typename lucet_detail::convert_type_to_wasm_type<T_Ret>::type ret,
    typename lucet_detail::convert_type_to_wasm_type<T_Args>::type... params)
  {
    thread_data.last_callback_invoked = N;
    using T_Func = T_Ret (*)(T_Args...);
    T_Func func;
    {
      rlbox_acquire_shared_guard(lock, thread_data.sandbox->callback_mutex);
      func = reinterpret_cast<T_Func>(thread_data.sandbox->callbacks[N]);
    }
    // Callbacks are invoked through function pointers, cannot use std::forward
    // as we don't have caller context for T_Args, which means they are all
    // effectively passed by value
    auto ret_val =
      func(thread_data.sandbox->serialize_to_sandbox<T_Args>(params)...);
    // Copy the return value back
    auto ret_ptr = reinterpret_cast<T_Ret*>(
      thread_data.sandbox->template impl_get_unsandboxed_pointer<T_Ret*>(ret));
    *ret_ptr = ret_val;
  }

  template<typename T_Ret, typename... T_Args>
  inline T_PointerType get_lucet_type_index(
    T_Ret (*/* dummy for template inference */)(T_Args...) = nullptr) const
  {
    // Class return types as promoted to args
    constexpr bool promoted = std::is_class_v<T_Ret>;
    int32_t type_index;

    if constexpr (promoted) {
      LucetValueType ret_type = LucetValueType::LucetValueType_Void;
      LucetValueType param_types[] = {
        lucet_detail::convert_type_to_wasm_type<T_Ret>::lucet_type,
        lucet_detail::convert_type_to_wasm_type<T_Args>::lucet_type...
      };
      LucetFunctionSignature signature{ ret_type,
                                        sizeof(param_types) /
                                          sizeof(LucetValueType),
                                        &(param_types[0]) };
      type_index = lucet_get_function_type_index(sandbox, signature);
    } else {
      LucetValueType ret_type =
        lucet_detail::convert_type_to_wasm_type<T_Ret>::lucet_type;
      LucetValueType param_types[] = {
        lucet_detail::convert_type_to_wasm_type<T_Args>::lucet_type...
      };
      LucetFunctionSignature signature{ ret_type,
                                        sizeof(param_types) /
                                          sizeof(LucetValueType),
                                        &(param_types[0]) };
      type_index = lucet_get_function_type_index(sandbox, signature);
    }

    return type_index;
  }

protected:
  inline void impl_create_sandbox(const char* lucet_module_path)
  {
    detail::dynamic_check(sandbox == nullptr, "Sandbox already initialized");
    sandbox = lucet_load_module(lucet_module_path);
    detail::dynamic_check(sandbox != nullptr, "Sandbox could not be created");

    heap_base = reinterpret_cast<uintptr_t>(impl_get_memory_location());
    // Check that the address space is larger than the sandbox heap i.e. 4GB
    // sandbox heap, host has to have more than 4GB
    static_assert(sizeof(uintptr_t) > sizeof(T_PointerType));
    // Check that the heap is aligned to the pointer size i.e. 32-bit pointer =>
    // aligned to 4GB. The implementations of
    // impl_get_unsandboxed_pointer_no_ctx and impl_get_sandboxed_pointer_no_ctx
    // below rely on this.
    uintptr_t heap_offset_mask = std::numeric_limits<T_PointerType>::max();
    detail::dynamic_check((heap_base & heap_offset_mask) == 0,
                          "Sandbox heap not aligned to 4GB");

    // cache these for performance
    malloc_index = impl_lookup_symbol("malloc");
    free_index = impl_lookup_symbol("free");

    set_callbacks_slots_ref();
  }

  inline void impl_destroy_sandbox() { lucet_drop_module(sandbox); }

  template<typename T>
  inline void* impl_get_unsandboxed_pointer(T_PointerType p) const
  {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      LucetFunctionTable functionPointerTable =
        lucet_get_function_pointer_table(sandbox);
      if (p >= functionPointerTable.length) {
        // Received out of range function pointer
        return nullptr;
      }
      auto ret = functionPointerTable.data[p].rf;
      return reinterpret_cast<void*>(static_cast<uintptr_t>(ret));
    } else {
      return reinterpret_cast<void*>(heap_base + p);
    }
  }

  template<typename T>
  inline T_PointerType impl_get_sandboxed_pointer(const void* p) const
  {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      // p is a pointer to a function internal to the lucet module
      // we need to either
      // 1) find the indirect function slot this is registered and return the
      // slot number. For this we need to scan the full indirect function table,
      // not just the portion we have reserved for callbacks.
      // 2) in the scenario this function has not ever been listed as an
      // indirect function, we need to register this like a normal callback.
      // However, unlike callbacks, we will not require the user to unregister
      // this. Instead, this permenantly takes up a callback slot.
      LucetFunctionTable functionPointerTable =
        lucet_get_function_pointer_table(sandbox);
      std::lock_guard<std::mutex> lock(callback_table_mutex);

      // Scenario 1 described above
      ssize_t empty_slot = -1;
      for (size_t i = 0; i < functionPointerTable.length; i++) {
        if (functionPointerTable.data[i].rf == reinterpret_cast<uintptr_t>(p)) {
          return static_cast<T_PointerType>(i);
        } else if (functionPointerTable.data[i].rf == 0 && empty_slot == -1) {
          // found an empty slot. Save it, as we may use it later.
          empty_slot = i;
        }
      }

      // Scenario 2 described above
      detail::dynamic_check(
        empty_slot != -1,
        "Could not find an empty slot in sandbox function table. This would "
        "happen if you have registered too many callbacks, or unsandboxed "
        "too many function pointers. You can file a bug if you want to "
        "increase the maximum allowed callbacks or unsadnboxed functions "
        "pointers");
      T dummy = nullptr;
      int32_t type_index = get_lucet_type_index(dummy);
      functionPointerTable.data[empty_slot].ty = type_index;
      functionPointerTable.data[empty_slot].rf = reinterpret_cast<uintptr_t>(p);
      return empty_slot;

    } else {
      return static_cast<T_PointerType>(reinterpret_cast<uintptr_t>(p));
    }
  }

  template<typename T>
  static inline void* impl_get_unsandboxed_pointer_no_ctx(
    T_PointerType p,
    const void* example_unsandboxed_ptr,
    rlbox_lucet_sandbox* (*expensive_sandbox_finder)(
      const void* example_unsandboxed_ptr))
  {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      // swizzling function pointers needs access to the function pointer tables
      // and thus cannot be done without context
      auto sandbox = expensive_sandbox_finder(example_unsandboxed_ptr);
      return sandbox->impl_get_unsandboxed_pointer<T>(p);
    } else {
      // grab the memory base from the example_unsandboxed_ptr
      uintptr_t heap_base_mask =
        std::numeric_limits<uintptr_t>::max() &
        ~(static_cast<uintptr_t>(std::numeric_limits<T_PointerType>::max()));
      uintptr_t computed_heap_base =
        reinterpret_cast<uintptr_t>(example_unsandboxed_ptr) & heap_base_mask;
      uintptr_t ret = computed_heap_base | p;
      return reinterpret_cast<void*>(ret);
    }
  }

  template<typename T>
  static inline T_PointerType impl_get_sandboxed_pointer_no_ctx(
    const void* p,
    const void* example_unsandboxed_ptr,
    rlbox_lucet_sandbox* (*expensive_sandbox_finder)(
      const void* example_unsandboxed_ptr))
  {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      // swizzling function pointers needs access to the function pointer tables
      // and thus cannot be done without context
      auto sandbox = expensive_sandbox_finder(example_unsandboxed_ptr);
      return sandbox->impl_get_sandboxed_pointer<T>(p);
    } else {
      // Just clear the memory base to leave the offset
      RLBOX_LUCET_UNUSED(example_unsandboxed_ptr);
      uintptr_t ret = reinterpret_cast<uintptr_t>(p) &
                      std::numeric_limits<T_PointerType>::max();
      return static_cast<T_PointerType>(ret);
    }
  }

  static inline bool impl_is_in_same_sandbox(const void* p1, const void* p2)
  {
    uintptr_t heap_base_mask = std::numeric_limits<uintptr_t>::max() &
                               ~(std::numeric_limits<T_PointerType>::max());
    return (reinterpret_cast<uintptr_t>(p1) & heap_base_mask) ==
           (reinterpret_cast<uintptr_t>(p2) & heap_base_mask);
  }

  inline bool impl_is_pointer_in_sandbox_memory(const void* p)
  {
    size_t length = impl_get_total_memory();
    uintptr_t p_val = reinterpret_cast<uintptr_t>(p);
    return p_val >= heap_base && p_val < (heap_base + length);
  }

  inline bool impl_is_pointer_in_app_memory(const void* p)
  {
    return !(impl_is_pointer_in_sandbox_memory(p));
  }

  inline size_t impl_get_total_memory() { return lucet_get_heap_size(sandbox); }

  inline void* impl_get_memory_location()
  {
    return lucet_get_heap_base(sandbox);
  }

  void* impl_lookup_symbol(const char* func_name)
  {
    return lucet_lookup_function(sandbox, func_name);
  }

  template<typename T, typename T_Converted, typename... T_Args>
  auto impl_invoke_with_func_ptr(T_Converted* func_ptr, T_Args&&... params)
  {
    thread_data.sandbox = this;
    void* func_ptr_void = reinterpret_cast<void*>(func_ptr);
    // Add one as the return value may require an arg slot for structs
    T_PointerType allocations[1 + sizeof...(params)];
    LucetValue args[1 + sizeof...(params)];
    serialize_return_and_args(
      &(allocations[0]), &(args[0]), func_ptr, std::forward<T_Args>(params)...);

    using T_Ret = lucet_detail::return_argument<T_Converted>;
    constexpr size_t alloc_length = (std::is_class_v<T_Ret> ? 1 : 0) + [&]() {
      if constexpr (sizeof...(params) > 0) {
        return ((std::is_class_v<T_Args> ? 1 : 0) + ...);
      } else {
        return 0;
      }
    }();

    constexpr size_t arg_length =
      sizeof...(params) + (std::is_class_v<T_Ret> ? 1 : 0);

    // struct returns are returned as pointers
    using T_Wasm_Ret =
      typename lucet_detail::convert_type_to_wasm_type<T_Ret>::type;

    if constexpr (std::is_void_v<T_Wasm_Ret>) {
      lucet_run_function_return_void(
        sandbox, func_ptr_void, arg_length, &(args[0]));
      for (size_t i = 0; i < alloc_length; i++) {
        impl_free_in_sandbox(allocations[i]);
      }
      return;
    } else {

      T_Wasm_Ret ret;
      if constexpr (std::is_class_v<T_Ret>) {
        lucet_run_function_return_void(
          sandbox, func_ptr_void, arg_length, &(args[0]));
        ret = allocations[0];
      } else if constexpr (std::is_same_v<T_Wasm_Ret, uint32_t>) {
        ret = lucet_run_function_return_u32(
          sandbox, func_ptr_void, arg_length, &(args[0]));
      } else if constexpr (std::is_same_v<T_Wasm_Ret, uint64_t>) {
        ret = lucet_run_function_return_u64(
          sandbox, func_ptr_void, arg_length, &(args[0]));
      } else if constexpr (std::is_same_v<T_Wasm_Ret, float>) {
        ret = lucet_run_function_return_f32(
          sandbox, func_ptr_void, arg_length, &(args[0]));
      } else if constexpr (std::is_same_v<T_Wasm_Ret, double>) {
        ret = lucet_run_function_return_f64(
          sandbox, func_ptr_void, arg_length, &(args[0]));
      } else {
        static_assert(lucet_detail::false_v<T_Wasm_Ret>,
                      "Unknown invoke return type");
      }

      auto serialized_ret = serialize_to_sandbox<T_Ret>(ret);
      // free only after serializing return, as return values such as structs
      // are returned as pointers which we must free
      for (size_t i = 0; i < alloc_length; i++) {
        impl_free_in_sandbox(allocations[i]);
      }
      return serialized_ret;
    }
  }

  inline T_PointerType impl_malloc_in_sandbox(size_t size)
  {
    detail::dynamic_check(size <= std::numeric_limits<uint32_t>::max(),
                          "Attempting to malloc more than the heap size");
    using T_Func = void*(size_t);
    using T_Converted = T_PointerType(uint32_t);
    T_PointerType ret = impl_invoke_with_func_ptr<T_Func, T_Converted>(
      reinterpret_cast<T_Converted*>(malloc_index),
      static_cast<uint32_t>(size));
    return ret;
  }

  inline void impl_free_in_sandbox(T_PointerType p)
  {
    using T_Func = void(void*);
    using T_Converted = void(T_PointerType);
    impl_invoke_with_func_ptr<T_Func, T_Converted>(
      reinterpret_cast<T_Converted*>(free_index), p);
  }

  template<typename T_Ret, typename... T_Args>
  inline T_PointerType impl_register_callback(void* key, void* callback)
  {
    int32_t type_index = get_lucet_type_index<T_Ret, T_Args...>();

    detail::dynamic_check(
      type_index != -1,
      "Could not find lucet type for callback signature. This can "
      "happen if you tried to register a callback whose signature "
      "does not correspond to any callbacks used in the library.");

    bool found = false;
    uint32_t slot_number = 0;

    {
      std::lock_guard<std::mutex> lock(callback_table_mutex);

      // need a compile time for loop as we we need I to be a compile time value
      // this is because we are setting the I'th callback ineterceptor
      lucet_detail::compile_time_for<MAX_CALLBACKS>([&](auto I) {
        constexpr auto i = I.value;
        if (!found && callback_slots->elements[i]->rf == 0) {
          found = true;
          slot_number = callback_slots->slot_number[i];
          {
            rlbox_acquire_unique_guard(lock, callback_mutex);
            callback_unique_keys[i] = key;
            callbacks[i] = callback;
            callback_slot_assignment[i] = slot_number;
          }
          void* chosen_interceptor;
          if constexpr (std::is_class_v<T_Ret>) {
            chosen_interceptor = reinterpret_cast<void*>(
              callback_interceptor_promoted<i, T_Ret, T_Args...>);
          } else {
            chosen_interceptor = reinterpret_cast<void*>(
              callback_interceptor<i, T_Ret, T_Args...>);
          }
          callback_slots->elements[i]->ty = type_index;
          callback_slots->elements[i]->rf =
            reinterpret_cast<uintptr_t>(chosen_interceptor);
        }
      });
    }

    detail::dynamic_check(
      found,
      "Could not find an empty slot in sandbox function table. This would "
      "happen if you have registered too many callbacks, or unsandboxed "
      "too many function pointers. You can file a bug if you want to "
      "increase the maximum allowed callbacks or unsadnboxed functions "
      "pointers");

    return static_cast<T_PointerType>(slot_number);
  }

  static inline std::pair<rlbox_lucet_sandbox*, void*>
  impl_get_executed_callback_sandbox_and_key()
  {
    auto sandbox = thread_data.sandbox;
    auto callback_num = thread_data.last_callback_invoked;
    void* key = sandbox->callback_unique_keys[callback_num];
    return std::make_pair(sandbox, key);
  }

  template<typename T_Ret, typename... T_Args>
  inline void impl_unregister_callback(void* key)
  {
    bool found = false;
    uint32_t i = 0;
    {
      rlbox_acquire_unique_guard(lock, callback_mutex);
      for (; i < MAX_CALLBACKS; i++) {
        if (callback_unique_keys[i] == key) {
          callback_unique_keys[i] = nullptr;
          callbacks[i] = nullptr;
          callback_slot_assignment[i] = 0;
          found = true;
          break;
        }
      }
    }

    if (found) {
      uint32_t slot_number = callback_slot_assignment[i];
      std::lock_guard<std::mutex> shared_lock(callback_table_mutex);
      callback_slots->elements[slot_number]->rf = 0;
      return;
    }
    detail::dynamic_check(
      false, "Internal error: Could not find callback to unregister");
  }
};

} // namespace rlbox