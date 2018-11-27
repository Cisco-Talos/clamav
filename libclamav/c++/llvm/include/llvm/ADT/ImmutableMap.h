//===--- ImmutableMap.h - Immutable (functional) map interface --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the ImmutableMap class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_IMMAP_H
#define LLVM_ADT_IMMAP_H

#include "llvm/ADT/ImmutableSet.h"

namespace llvm {

/// ImutKeyValueInfo -Traits class used by ImmutableMap.  While both the first
/// and second elements in a pair are used to generate profile information,
/// only the first element (the key) is used by isEqual and isLess.
template <typename T, typename S>
struct ImutKeyValueInfo {
  typedef const std::pair<T,S> value_type;
  typedef const value_type& value_type_ref;
  typedef const T   key_type;
  typedef const T&  key_type_ref;
  typedef const S   data_type;
  typedef const S&  data_type_ref;

  static inline key_type_ref KeyOfValue(value_type_ref V) {
    return V.first;
  }

  static inline data_type_ref DataOfValue(value_type_ref V) {
    return V.second;
  }

  static inline bool isEqual(key_type_ref L, key_type_ref R) {
    return ImutContainerInfo<T>::isEqual(L,R);
  }
  static inline bool isLess(key_type_ref L, key_type_ref R) {
    return ImutContainerInfo<T>::isLess(L,R);
  }

  static inline bool isDataEqual(data_type_ref L, data_type_ref R) {
    return ImutContainerInfo<S>::isEqual(L,R);
  }

  static inline void Profile(FoldingSetNodeID& ID, value_type_ref V) {
    ImutContainerInfo<T>::Profile(ID, V.first);
    ImutContainerInfo<S>::Profile(ID, V.second);
  }
};


template <typename KeyT, typename ValT,
          typename ValInfo = ImutKeyValueInfo<KeyT,ValT> >
class ImmutableMap {
public:
  typedef typename ValInfo::value_type      value_type;
  typedef typename ValInfo::value_type_ref  value_type_ref;
  typedef typename ValInfo::key_type        key_type;
  typedef typename ValInfo::key_type_ref    key_type_ref;
  typedef typename ValInfo::data_type       data_type;
  typedef typename ValInfo::data_type_ref   data_type_ref;
  typedef ImutAVLTree<ValInfo>              TreeTy;

protected:
  TreeTy* Root;

public:
  /// Constructs a map from a pointer to a tree root.  In general one
  /// should use a Factory object to create maps instead of directly
  /// invoking the constructor, but there are cases where make this
  /// constructor public is useful.
  explicit ImmutableMap(const TreeTy* R) : Root(const_cast<TreeTy*>(R)) {}

  class Factory {
    typename TreeTy::Factory F;
    const bool Canonicalize;

  public:
    Factory(bool canonicalize = true)
      : Canonicalize(canonicalize) {}
    
    Factory(BumpPtrAllocator& Alloc, bool canonicalize = true)
      : F(Alloc), Canonicalize(canonicalize) {}

    ImmutableMap GetEmptyMap() { return ImmutableMap(F.GetEmptyTree()); }

    ImmutableMap Add(ImmutableMap Old, key_type_ref K, data_type_ref D) {
      TreeTy *T = F.Add(Old.Root, std::pair<key_type,data_type>(K,D));
      return ImmutableMap(Canonicalize ? F.GetCanonicalTree(T): T);
    }

    ImmutableMap Remove(ImmutableMap Old, key_type_ref K) {
      TreeTy *T = F.Remove(Old.Root,K);
      return ImmutableMap(Canonicalize ? F.GetCanonicalTree(T): T);
    }

  private:
    Factory(const Factory& RHS); // DO NOT IMPLEMENT
    void operator=(const Factory& RHS); // DO NOT IMPLEMENT
  };

  bool contains(key_type_ref K) const {
    return Root ? Root->contains(K) : false;
  }

  bool operator==(ImmutableMap RHS) const {
    return Root && RHS.Root ? Root->isEqual(*RHS.Root) : Root == RHS.Root;
  }

  bool operator!=(ImmutableMap RHS) const {
    return Root && RHS.Root ? Root->isNotEqual(*RHS.Root) : Root != RHS.Root;
  }

  TreeTy* getRoot() const { return Root; }

  bool isEmpty() const { return !Root; }

  //===--------------------------------------------------===//
  // Foreach - A limited form of map iteration.
  //===--------------------------------------------------===//

private:
  template <typename Callback>
  struct CBWrapper {
    Callback C;
    void operator()(value_type_ref V) { C(V.first,V.second); }
  };

  template <typename Callback>
  struct CBWrapperRef {
    Callback &C;
    CBWrapperRef(Callback& c) : C(c) {}

    void operator()(value_type_ref V) { C(V.first,V.second); }
  };

public:
  template <typename Callback>
  void foreach(Callback& C) {
    if (Root) {
      CBWrapperRef<Callback> CB(C);
      Root->foreach(CB);
    }
  }

  template <typename Callback>
  void foreach() {
    if (Root) {
      CBWrapper<Callback> CB;
      Root->foreach(CB);
    }
  }

  //===--------------------------------------------------===//
  // For testing.
  //===--------------------------------------------------===//

  void verify() const { if (Root) Root->verify(); }

  //===--------------------------------------------------===//
  // Iterators.
  //===--------------------------------------------------===//

  class iterator {
    typename TreeTy::iterator itr;

    iterator() {}
    iterator(TreeTy* t) : itr(t) {}
    friend class ImmutableMap;

  public:
    value_type_ref operator*() const { return itr->getValue(); }
    value_type*    operator->() const { return &itr->getValue(); }

    key_type_ref getKey() const { return itr->getValue().first; }
    data_type_ref getData() const { return itr->getValue().second; }


    iterator& operator++() { ++itr; return *this; }
    iterator  operator++(int) { iterator tmp(*this); ++itr; return tmp; }
    iterator& operator--() { --itr; return *this; }
    iterator  operator--(int) { iterator tmp(*this); --itr; return tmp; }
    bool operator==(const iterator& RHS) const { return RHS.itr == itr; }
    bool operator!=(const iterator& RHS) const { return RHS.itr != itr; }
  };

  iterator begin() const { return iterator(Root); }
  iterator end() const { return iterator(); }

  data_type* lookup(key_type_ref K) const {
    if (Root) {
      TreeTy* T = Root->find(K);
      if (T) return &T->getValue().second;
    }

    return 0;
  }
  
  /// getMaxElement - Returns the <key,value> pair in the ImmutableMap for
  ///  which key is the highest in the ordering of keys in the map.  This
  ///  method returns NULL if the map is empty.
  value_type* getMaxElement() const {
    return Root ? &(Root->getMaxElement()->getValue()) : 0;
  }

  //===--------------------------------------------------===//
  // Utility methods.
  //===--------------------------------------------------===//

  unsigned getHeight() const { return Root ? Root->getHeight() : 0; }

  static inline void Profile(FoldingSetNodeID& ID, const ImmutableMap& M) {
    ID.AddPointer(M.Root);
  }

  inline void Profile(FoldingSetNodeID& ID) const {
    return Profile(ID,*this);
  }
};

} // end namespace llvm

#endif
