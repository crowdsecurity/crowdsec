//go:build tinygo.wasm || re2_cgo

/*
  Source  file	for  CRE2, a  C	 language  wrapper  for RE2:  a	 regular
  expressions library by Google.

  Copyright (c) 2012, 2016, 2019 Marco Maggi <mrc.mgg@gmail.com>
  Copyright (c) 2011 Keegan McAllister
  All rights reserved.

  For the license notice see the COPYING file.
*/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif
#include <re2/re2.h>
#include <re2/set.h>
#include "cre2.h"

#include <cstdlib>
#include <cstdio>
#include <vector>


/** --------------------------------------------------------------------
 ** Options objects.
 ** ----------------------------------------------------------------- */

/* Cast	  the	pointer	  argument   "opt"   to	 a   pointer   of   type
   "RE2::Options*". */
#define TO_OPT(opt) (reinterpret_cast<RE2::Options *>(opt))

cre2_options_t *
cre2_opt_new(void)
/* Allocate and return a new options object. */
{
  // FIXME: is	this use of  "nothrow" good to avoid  raising exceptions
  // when memory allocation fails and to return NULL instead?
  return reinterpret_cast<void*>(new (std::nothrow) RE2::Options());
}
void
cre2_opt_delete (cre2_options_t *opt)
/* Finalise an options object. */
{
  delete TO_OPT(opt);
}

/* Set or unset option flags in an options object. */
#define OPT_BOOL(name)	\
 void cre2_opt_set_##name (cre2_options_t *opt, int flag)	\
 {								\
   TO_OPT(opt)->set_##name(bool(flag));				\
 }								\
 int cre2_opt_##name (cre2_options_t *opt)			\
 {								\
   return TO_OPT(opt)->name();					\
 }
OPT_BOOL(posix_syntax)
OPT_BOOL(longest_match)
OPT_BOOL(log_errors)
OPT_BOOL(literal)
OPT_BOOL(never_nl)
OPT_BOOL(dot_nl)
OPT_BOOL(never_capture)
OPT_BOOL(case_sensitive)
OPT_BOOL(perl_classes)
OPT_BOOL(word_boundary)
OPT_BOOL(one_line)
#undef OPT_BOOL

void
cre2_opt_set_encoding (cre2_options_t *opt, cre2_encoding_t enc)
/* Select the encoding in an options object. */
{
  switch (enc) {
  case CRE2_UTF8:
    TO_OPT(opt)->set_encoding(RE2::Options::EncodingUTF8);
    break;
  case CRE2_Latin1:
    TO_OPT(opt)->set_encoding(RE2::Options::EncodingLatin1);
    break;
  default:
    fprintf(stderr, "CRE2: internal error: unknown encoding %d\n", enc);
    exit(EXIT_FAILURE);
  }
}
cre2_encoding_t
cre2_opt_encoding (cre2_options_t *opt)
{
  RE2::Options::Encoding	E = TO_OPT(opt)->encoding();
  switch (E) {
  case RE2::Options::EncodingUTF8:
    return CRE2_UTF8;
  case RE2::Options::EncodingLatin1:
    return CRE2_Latin1;
  default:
    return CRE2_UNKNOWN;
  }
}
void
cre2_opt_set_max_mem (cre2_options_t *opt, int64_t m)
/* Configure the maximum amount of memory in an options object. */
{
  TO_OPT(opt)->set_max_mem(m);
}
int64_t
cre2_opt_max_mem (cre2_options_t *opt)
{
  return TO_OPT(opt)->max_mem();
}
void
cre2_opt_set_latin1_encoding(cre2_options_t *opt)
{
  TO_OPT(opt)->set_encoding(RE2::Options::EncodingLatin1);
}


/** --------------------------------------------------------------------
 ** Precompiled regular expressions objects.
 ** ----------------------------------------------------------------- */

#define TO_RE2(re)	 (reinterpret_cast<RE2 *>(re))
#define TO_CONST_RE2(re) (reinterpret_cast<const RE2 *>(re))

cre2_regexp_t *
cre2_new (const char *pattern, int pattern_len, const cre2_options_t *opt)
{
  re2::StringPiece pattern_re2(pattern, pattern_len);
  if (opt) {
    // FIXME:  is  this	 use   of  "nothrow"  enough  to  avoid	 raising
    // exceptions  when	 memory	 allocation  fails and	to  return  NULL
    // instead?
    return reinterpret_cast<void*>
      (new (std::nothrow) RE2(pattern_re2, *reinterpret_cast<const RE2::Options *>(opt)));
  } else {
    return reinterpret_cast<void*> (new (std::nothrow) RE2(pattern_re2));
  }
}
void
cre2_delete (cre2_regexp_t *re)
{
  delete TO_RE2(re);
}
const char *
cre2_pattern (const cre2_regexp_t *re)
{
  return TO_CONST_RE2(re)->pattern().c_str();
}
int
cre2_error_code (const cre2_regexp_t *re)
{
  return int(TO_CONST_RE2(re)->error_code());
}
const char *
cre2_error_string (const cre2_regexp_t *re)
{
  return TO_CONST_RE2(re)->error().c_str();
}
void
cre2_error_arg (const cre2_regexp_t *re, cre2_string_t *arg)
{
  const std::string &argstr = TO_CONST_RE2(re)->error_arg();
  arg->data   = argstr.data();
  arg->length = argstr.length();
}
int
cre2_num_capturing_groups (const cre2_regexp_t *re)
{
  return TO_CONST_RE2(re)->NumberOfCapturingGroups();
}
int
cre2_find_named_capturing_groups (const cre2_regexp_t *re, const char* group_name)
{
  const std::map<std::string, int>& m = TO_CONST_RE2(re)->NamedCapturingGroups();
  std::map<std::string, int>::const_iterator it = m.find(group_name);

  if(it != m.end()) {
    return it->second;
  }
  else {
    return -1;
  }
}

int
cre2_program_size (const cre2_regexp_t *re)
{
  return TO_CONST_RE2(re)->ProgramSize();
}


/** --------------------------------------------------------------------
 ** Named capture group iteration.
 ** ----------------------------------------------------------------- */

struct cre2_named_groups_iter_t
{
  const RE2 * re;
  std::map<int, std::string>::const_iterator it;
};

cre2_named_groups_iter_t *
cre2_named_groups_iter_new(const cre2_regexp_t *re)
{
  cre2_named_groups_iter_t * iter = new (std::nothrow)cre2_named_groups_iter_t;
  iter->re = TO_CONST_RE2(re);
  iter->it = iter->re->CapturingGroupNames().begin();
  return iter;
}
bool
cre2_named_groups_iter_next(cre2_named_groups_iter_t* iter, const char ** name, int *index)
{
  if (iter->it == iter->re->CapturingGroupNames().end()) {
    *name = NULL;
    *index = -1;
    return false;
  } else {
    *index = iter->it->first;
    *name = iter->it->second.c_str();
    ++iter->it;
    return true;
  }
}
void
cre2_named_groups_iter_delete(cre2_named_groups_iter_t *iter)
{
  delete iter;
}


/** --------------------------------------------------------------------
 ** Matching with precompiled regular expressions objects.
 ** ----------------------------------------------------------------- */

static RE2::Anchor
to_cre2_anchor(cre2_anchor_t anchor)
{
  RE2::Anchor anchor_re2 = RE2::UNANCHORED;
  switch (anchor) {
  case CRE2_ANCHOR_START:
    anchor_re2 = RE2::ANCHOR_START;
    break;
  case CRE2_ANCHOR_BOTH:
    anchor_re2 = RE2::ANCHOR_BOTH;
    break;
  case CRE2_UNANCHORED:
    break;
  }
  return anchor_re2;
}

int
cre2_match (const cre2_regexp_t *re , const char *text,
	    int textlen, int startpos, int endpos, cre2_anchor_t anchor,
	    cre2_string_t *match, int nmatch)
{
  re2::StringPiece	text_re2(text, textlen);
  std::vector<re2::StringPiece>	match_re2(nmatch);
  RE2::Anchor		anchor_re2 = to_cre2_anchor(anchor);
  bool			retval; // 0 for no match
				// 1 for successful matching
  retval = TO_CONST_RE2(re)->Match(text_re2, startpos, endpos, anchor_re2, match_re2.data(), nmatch);
  if (retval) {
    for (int i=0; i<nmatch; i++) {
      match[i].data   = match_re2[i].data();
      match[i].length = match_re2[i].length();
    }
  }
  return (retval)? 1 : 0;
}
int
cre2_easy_match (const char * pattern, int pattern_len,
		 const char *text, int text_len,
		 cre2_string_t *match, int nmatch)
{
  cre2_regexp_t *	rex;
  cre2_options_t *	opt;
  int			retval; // 0  for  no  match, 1	 for  successful
				// matching, 2 for wrong regexp
  opt	= cre2_opt_new();
  if (!opt) return 2;
  cre2_opt_set_log_errors(opt, 0);
  rex	= cre2_new(pattern, pattern_len, opt);
  if (!rex) {
    cre2_opt_delete(opt);
    return 2;
  }
  {
    if (!cre2_error_code(rex)) {
      retval = cre2_match(rex, text, text_len, 0, text_len, CRE2_UNANCHORED, match, nmatch);
    } else {
      retval = 2;
    }
  }
  cre2_delete(rex);
  cre2_opt_delete(opt);
  return retval;
}
void
cre2_strings_to_ranges (const char * text, cre2_range_t * ranges, cre2_string_t * strings, int nmatch)
{
  for (int i=0; i<nmatch; ++i) {
    ranges[i].start = strings[i].data - text;
    ranges[i].past  = ranges[i].start + strings[i].length;
  }
}


/** --------------------------------------------------------------------
 ** Other matching functions: stringz pattern.
 ** ----------------------------------------------------------------- */

#define DEFINE_MATCH_ZSTRING_FUN(NAME,FUN)				\
  int									\
  NAME (const char * pattern, const cre2_string_t * text,		\
	cre2_string_t * match, int nmatch)				\
  {									\
    re2::StringPiece	input(text->data, text->length);		\
    std::vector<re2::StringPiece>	strv(nmatch);			\
    std::vector<RE2::Arg>		argv(nmatch);			\
    std::vector<RE2::Arg*>		args(nmatch);			\
    bool				retval;				\
    for (int i=0; i<nmatch; ++i) {					\
      argv[i] = &(strv.data())[i];					\
      args[i] = &(argv.data())[i];					\
    }									\
    retval = RE2::FUN(input, pattern, args.data(), nmatch);		\
    if (retval) {							\
      for (int i=0; i<nmatch; ++i) {					\
	match[i].data	= strv[i].data();				\
	match[i].length = strv[i].length();				\
      }									\
    }									\
    return int(retval);							\
  }

DEFINE_MATCH_ZSTRING_FUN(cre2_full_match,FullMatchN)
DEFINE_MATCH_ZSTRING_FUN(cre2_partial_match,PartialMatchN)

/* This	 is different from  the above  in that	the "input"  argument is
   mutated to reference the text after the mathing portion. */
#define DEFINE_MATCH_ZSTRING_FUN2(NAME,FUN)				\
  int									\
  NAME (const char * pattern, cre2_string_t * text,			\
	cre2_string_t * match, int nmatch)				\
  {									\
    re2::StringPiece	input(text->data, text->length);		\
    std::vector<re2::StringPiece>	strv(nmatch);			\
    std::vector<RE2::Arg>		argv(nmatch);			\
    std::vector<RE2::Arg*>		args(nmatch);			\
    bool				retval;				\
    for (int i=0; i<nmatch; ++i) {					\
      argv[i] = &(strv.data())[i];					\
      args[i] = &(argv.data())[i];					\
    }									\
    retval = RE2::FUN(&input, pattern, args.data(), nmatch);		\
    if (retval) {							\
      text->data   = input.data();					\
      text->length = input.length();					\
      for (int i=0; i<nmatch; ++i) {					\
	match[i].data	= strv[i].data();				\
	match[i].length = strv[i].length();				\
      }									\
    }									\
    return int(retval);							\
  }

DEFINE_MATCH_ZSTRING_FUN2(cre2_consume,ConsumeN)
DEFINE_MATCH_ZSTRING_FUN2(cre2_find_and_consume,FindAndConsumeN)


/** --------------------------------------------------------------------
 ** Other matching functions: rex pattern.
 ** ----------------------------------------------------------------- */

#define DEFINE_MATCH_REX_FUN(NAME,FUN)					\
  int									\
  NAME (cre2_regexp_t * rex, const cre2_string_t * text,		\
	cre2_string_t * match, int nmatch)				\
  {									\
    re2::StringPiece	input(text->data, text->length);		\
    std::vector<re2::StringPiece>	strv(nmatch);			\
    std::vector<RE2::Arg>		argv(nmatch);			\
    std::vector<RE2::Arg*>		args(nmatch);			\
    bool				retval;				\
    for (int i=0; i<nmatch; ++i) {					\
      argv[i] = &(strv.data())[i];					\
      args[i] = &(argv.data())[i];					\
    }									\
    retval = RE2::FUN(input, *TO_RE2(rex), args.data(), nmatch);	\
    if (retval) {							\
      for (int i=0; i<nmatch; ++i) {					\
	match[i].data	= strv[i].data();				\
	match[i].length = strv[i].length();				\
      }									\
    }									\
    return int(retval);							\
  }

DEFINE_MATCH_REX_FUN(cre2_full_match_re,FullMatchN)
DEFINE_MATCH_REX_FUN(cre2_partial_match_re,PartialMatchN)

/* This	 is different from  the above  in that	the "input"  argument is
   mutated to reference the text after the mathing portion. */
#define DEFINE_MATCH_REX_FUN2(NAME,FUN)					\
  int									\
  NAME (cre2_regexp_t * rex, cre2_string_t * text,			\
	cre2_string_t * match, int nmatch)				\
  {									\
    re2::StringPiece	input(text->data, text->length);		\
    std::vector<re2::StringPiece>	strv(nmatch);			\
    std::vector<RE2::Arg>		argv(nmatch);			\
    std::vector<RE2::Arg*>		args(nmatch);			\
    bool				retval;				\
    for (int i=0; i<nmatch; ++i) {					\
      argv[i] = &(strv.data())[i];					\
      args[i] = &(argv.data())[i];					\
    }									\
    retval = RE2::FUN(&input, *TO_RE2(rex), args.data(), nmatch);	\
    if (retval) {							\
      text->data   = input.data();					\
      text->length = input.length();					\
      for (int i=0; i<nmatch; ++i) {					\
	match[i].data	= strv[i].data();				\
	match[i].length = strv[i].length();				\
      }									\
    }									\
    return int(retval);							\
  }

DEFINE_MATCH_REX_FUN2(cre2_consume_re,ConsumeN)
DEFINE_MATCH_REX_FUN2(cre2_find_and_consume_re,FindAndConsumeN)


/** --------------------------------------------------------------------
 ** Problematic functions.
 ** ----------------------------------------------------------------- */

/* The following  functions rely  on C++ memory	 allocation.  It  is not
   clear how they can be written to allow a correct API towards C.  */

int
cre2_replace (const char * pattern, cre2_string_t * text_and_target, cre2_string_t * rewrite)
{
  std::string		S(text_and_target->data, text_and_target->length);
  re2::StringPiece	R(rewrite->data, rewrite->length);
  char *		buffer; /* this exists to make GCC shut up about const */
  bool		retval;
  retval = RE2::Replace(&S, pattern, R);
  text_and_target->length = S.length();
  buffer = (char *)malloc(1+text_and_target->length);
  if (buffer) {
    S.copy(buffer, text_and_target->length);
    buffer[text_and_target->length] = '\0';
    text_and_target->data = buffer;
  } else
    return -1;
  return int(retval);
}
int
cre2_replace_re (cre2_regexp_t * rex, cre2_string_t * text_and_target, cre2_string_t * rewrite)
{
  std::string		S(text_and_target->data, text_and_target->length);
  re2::StringPiece	R(rewrite->data, rewrite->length);
  char *		buffer; /* this exists to make GCC shut up about const */
  bool			retval;
  retval = RE2::Replace(&S, *TO_RE2(rex), R);
  text_and_target->length = S.length();
  buffer = (char *)malloc(1+text_and_target->length);
  if (buffer) {
    S.copy(buffer, text_and_target->length);
    buffer[text_and_target->length] = '\0';
    text_and_target->data = buffer;
  } else
    return -1;
  return int(retval);
}

/* ------------------------------------------------------------------ */

int
cre2_global_replace (const char * pattern, cre2_string_t * text_and_target, cre2_string_t * rewrite)
{
  std::string		S(text_and_target->data, text_and_target->length);
  re2::StringPiece	R(rewrite->data, rewrite->length);
  char *		buffer; /* this exists to make GCC shut up about const */
  int			retval;
  retval = RE2::GlobalReplace(&S, pattern, R);
  text_and_target->length = S.length();
  buffer = (char *)malloc(1+text_and_target->length);
  if (buffer) {
    S.copy(buffer, text_and_target->length);
    buffer[text_and_target->length] = '\0';
    text_and_target->data = buffer;
  } else
    return -1;
  return int(retval);
}
int
cre2_global_replace_re (cre2_regexp_t * rex, cre2_string_t * text_and_target, cre2_string_t * rewrite)
{
  std::string		S(text_and_target->data, text_and_target->length);
  re2::StringPiece	R(rewrite->data, rewrite->length);
  char *		buffer; /* this exists to make GCC shut up about const */
  int			retval;
  retval = RE2::GlobalReplace(&S, *TO_RE2(rex), R);
  text_and_target->length = S.length();
  buffer = (char *)malloc(1+text_and_target->length);
  if (buffer) {
    S.copy(buffer, text_and_target->length);
    buffer[text_and_target->length] = '\0';
    text_and_target->data = buffer;
  } else
    return -1;
  return retval;
}

/* ------------------------------------------------------------------ */

int
cre2_extract (const char * pattern, cre2_string_t * text,
	      cre2_string_t * rewrite, cre2_string_t * target)
{
  re2::StringPiece	T(text->data, text->length);
  re2::StringPiece	R(rewrite->data, rewrite->length);
  std::string		O;
  char *		buffer; /* this exists to make GCC shut up about const */
  bool			retval;
  retval = RE2::Extract(T, pattern, R, &O);
  target->length = O.length();
  buffer = (char *)malloc(1+target->length);
  if (buffer) {
    O.copy(buffer, target->length);
    buffer[target->length] = '\0';
    target->data = buffer;
  } else
    return -1;
  return int(retval);
}
int
cre2_extract_re (cre2_regexp_t * rex, cre2_string_t * text,
		 cre2_string_t * rewrite, cre2_string_t * target)
{
  re2::StringPiece	T(text->data, text->length);
  re2::StringPiece	R(rewrite->data, rewrite->length);
  std::string		O;
  char *		buffer; /* this exists to make GCC shut up about const */
  bool			retval;
  retval = RE2::Extract(T, *TO_RE2(rex), R, &O);
  target->length = O.length();
  buffer = (char *)malloc(1+target->length);
  if (buffer) {
    O.copy(buffer, target->length);
    buffer[target->length] = '\0';
    target->data = buffer;
  } else
    return -1;
  return int(retval);
}

/* ------------------------------------------------------------------ */

int
cre2_quote_meta (cre2_string_t * quoted, cre2_string_t * original)
{
  re2::StringPiece	O(original->data, original->length);
  std::string		Q;
  char *		buffer; /* this exists to make GCC shut up about const */
  Q = RE2::QuoteMeta(O);
  quoted->length = Q.length();
  buffer = (char *)malloc(1+quoted->length);
  if (buffer) {
    Q.copy(buffer, quoted->length);
    buffer[quoted->length] = '\0';
    quoted->data = buffer;
    return 0;
  } else
    return -1;
}
int
cre2_possible_match_range (cre2_regexp_t * rex,
			   cre2_string_t * min_, cre2_string_t * max_, int maxlen)
{
  std::string	MIN, MAX;
  cre2_string_t	min, max;
  char *	buffer; /* this exists to make GCC shut up about const */
  bool		retval;
  retval = TO_RE2(rex)->PossibleMatchRange(&MIN, &MAX, maxlen);
  if (retval) {
    /* copy MIN */
    min.length = MIN.length();
    buffer = (char *)malloc(1+min.length);
    if (buffer) {
      MIN.copy(buffer, min.length);
      buffer[min.length] = '\0';
      min.data = buffer;
    } else
      return -1;
    /* copy MAX */
    max.length = MAX.length();
    buffer = (char *)malloc(1+max.length);
    if (buffer) {
      MAX.copy(buffer, max.length);
      buffer[max.length] = '\0';
      max.data = buffer;
    } else {
      free((void *)min.data);
      min.data = NULL;
      return -1;
    }
    *min_ = min;
    *max_ = max;
    return 1;
  } else
    return 0;
}
int
cre2_check_rewrite_string (cre2_regexp_t * rex, cre2_string_t * rewrite, cre2_string_t * errmsg)
{
  re2::StringPiece	R(rewrite->data, rewrite->length);
  std::string		E;
  char *		buffer; /* this exists to make GCC shut up about const */
  bool			retval;
  retval = TO_RE2(rex)->CheckRewriteString(R, &E);
  if (retval) {
    errmsg->data   = NULL;
    errmsg->length = 0;
    return 1;
  } else {
    errmsg->length = E.length();
    buffer = (char *)malloc(1+errmsg->length);
    if (buffer) {
      E.copy(buffer, errmsg->length);
      buffer[errmsg->length] = '\0';
      errmsg->data = buffer;
    } else
      return -1;
    return 0;
  }
}


/** --------------------------------------------------------------------
 ** Set match.
 ** ----------------------------------------------------------------- */

#define TO_RE2_SET(set)   (reinterpret_cast<RE2::Set *>(set))
#define TO_CRE2_SET(set)  (reinterpret_cast<cre2_set *>(set))

// RE2::Set constructor and destructor
cre2_set*
cre2_set_new(cre2_options_t *opt, cre2_anchor_t anchor)
{
  return TO_CRE2_SET(new (std::nothrow) RE2::Set(*TO_OPT(opt), to_cre2_anchor(anchor)));
}

void
cre2_set_delete(cre2_set *set)
{
  delete TO_RE2_SET(set);
}

// Add a regex to the set. If invalid: store error message in error buffer.
int
cre2_set_add(cre2_set *set, const char *pattern, size_t pattern_len, char *error, size_t error_len)
{
  RE2::Set *s = TO_RE2_SET(set);
  re2::StringPiece regex(pattern, static_cast<int>(pattern_len));
  if ((NULL == error) || (0 == error_len)) {
    return s->Add(regex, NULL);
  } else {
    std::string err;
    int regex_index = s->Add(regex, &err);
    if (regex_index < 0) {
      size_t len = err.size() < error_len - 1 ? err.size() : error_len - 1;
      err.copy(error, len);
      error[len] = '\0';
    }
    return regex_index;
  }
}

// Add pattern without NULL byte. Don't store error message.
int
cre2_set_add_simple(cre2_set *set, const char *pattern)
{
  RE2::Set *s = TO_RE2_SET(set);
  re2::StringPiece regex(pattern, static_cast<int>(strlen(pattern)));
  return s->Add(regex, NULL);
}


// Compile the regex set into a DFA. Must be called after add and before match.
int
cre2_set_compile(cre2_set *set)
{
  RE2::Set *s = TO_RE2_SET(set);
  return static_cast<int>(s->Compile());
}

// Match the set of regex against text and store indices of matching regexes in match array.
// Returns the number of regexes which match.
size_t
cre2_set_match(cre2_set *set, const char *text, size_t text_len, int *match, size_t match_len)
{
  RE2::Set *s = TO_RE2_SET(set);
  re2::StringPiece data(text, static_cast<int>(text_len));
  std::vector<int> v;
  bool does_match = s->Match(data, &v);
  if (!does_match) {
    return 0;
  }
  size_t min = v.size() < match_len ? v.size() : match_len;
  std::copy(v.begin(), v.begin() + min, match);
  return v.size();
}

/* end of file */
