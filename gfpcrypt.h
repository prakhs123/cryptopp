#ifndef CRYPTOPP_GFPCRYPT_H
#define CRYPTOPP_GFPCRYPT_H

//! \file gfpcrypt.h
//! \brief Implementation of schemes based on DL over GF(p)

#include "config.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(push)
# pragma warning(disable: 4189)
#endif

#include "cryptlib.h"
#include "pubkey.h"
#include "integer.h"
#include "modexppc.h"
#include "algparam.h"
#include "smartptr.h"
#include "sha.h"
#include "asn.h"
#include "hmac.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

CRYPTOPP_DLL_TEMPLATE_CLASS DL_GroupParameters<Integer>;

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE DL_GroupParameters_IntegerBased : public ASN1CryptoMaterial<DL_GroupParameters<Integer> >
{
	typedef DL_GroupParameters_IntegerBased ThisClass;

public:
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_IntegerBased() {}
#endif

	void Initialize(const DL_GroupParameters_IntegerBased &params)
		{Initialize(params.GetModulus(), params.GetSubgroupOrder(), params.GetSubgroupGenerator());}
	void Initialize(RandomNumberGenerator &rng, unsigned int pbits)
		{GenerateRandom(rng, MakeParameters("ModulusSize", (int)pbits));}
	void Initialize(const Integer &p, const Integer &g)
		{SetModulusAndSubgroupGenerator(p, g); SetSubgroupOrder(ComputeGroupOrder(p)/2);}
	void Initialize(const Integer &p, const Integer &q, const Integer &g)
		{SetModulusAndSubgroupGenerator(p, g); SetSubgroupOrder(q);}

	// ASN1Object interface
	void BERDecode(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	// GeneratibleCryptoMaterial interface
	/*! parameters: (ModulusSize, SubgroupOrderSize (optional)) */
	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg);
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
	void AssignFrom(const NameValuePairs &source);

	// DL_GroupParameters
	const Integer & GetSubgroupOrder() const {return m_q;}
	Integer GetGroupOrder() const {return GetFieldType() == 1 ? GetModulus()-Integer::One() : GetModulus()+Integer::One();}
	bool ValidateGroup(RandomNumberGenerator &rng, unsigned int level) const;
	bool ValidateElement(unsigned int level, const Integer &element, const DL_FixedBasePrecomputation<Integer> *precomp) const;
	bool FastSubgroupCheckAvailable() const {return GetCofactor() == 2;}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	// Cygwin i386 crash at -O3; see .
	void EncodeElement(bool reversible, const Element &element, byte *encoded) const;
	unsigned int GetEncodedElementSize(bool reversible) const;
#else
	void EncodeElement(bool reversible, const Element &element, byte *encoded) const
		{CRYPTOPP_UNUSED(reversible); element.Encode(encoded, GetModulus().ByteCount());}
	unsigned int GetEncodedElementSize(bool reversible) const
		{CRYPTOPP_UNUSED(reversible); return GetModulus().ByteCount();}
#endif

	Integer DecodeElement(const byte *encoded, bool checkForGroupMembership) const;
	Integer ConvertElementToInteger(const Element &element) const
		{return element;}
	Integer GetMaxExponent() const;
	static std::string CRYPTOPP_API StaticAlgorithmNamePrefix() {return "";}

	OID GetAlgorithmID() const;

	virtual const Integer & GetModulus() const =0;
	virtual void SetModulusAndSubgroupGenerator(const Integer &p, const Integer &g) =0;

	void SetSubgroupOrder(const Integer &q)
		{m_q = q; ParametersChanged();}

protected:
	Integer ComputeGroupOrder(const Integer &modulus) const
		{return modulus-(GetFieldType() == 1 ? 1 : -1);}

	// GF(p) = 1, GF(p^2) = 2
	virtual int GetFieldType() const =0;
	virtual unsigned int GetDefaultSubgroupOrderSize(unsigned int modulusSize) const;

private:
	Integer m_q;
};

//! _
template <class GROUP_PRECOMP, class BASE_PRECOMP = DL_FixedBasePrecomputationImpl<CPP_TYPENAME GROUP_PRECOMP::Element> >
class CRYPTOPP_NO_VTABLE DL_GroupParameters_IntegerBasedImpl : public DL_GroupParametersImpl<GROUP_PRECOMP, BASE_PRECOMP, DL_GroupParameters_IntegerBased>
{
	typedef DL_GroupParameters_IntegerBasedImpl<GROUP_PRECOMP, BASE_PRECOMP> ThisClass;

public:
	typedef typename GROUP_PRECOMP::Element Element;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_IntegerBasedImpl() {}
#endif

	// GeneratibleCryptoMaterial interface
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
		{return GetValueHelper<DL_GroupParameters_IntegerBased>(this, name, valueType, pValue).Assignable();}

	void AssignFrom(const NameValuePairs &source)
		{AssignFromHelper<DL_GroupParameters_IntegerBased>(this, source);}

	// DL_GroupParameters
	const DL_FixedBasePrecomputation<Element> & GetBasePrecomputation() const {return this->m_gpc;}
	DL_FixedBasePrecomputation<Element> & AccessBasePrecomputation() {return this->m_gpc;}

	// IntegerGroupParameters
	const Integer & GetModulus() const {return this->m_groupPrecomputation.GetModulus();}
    const Integer & GetGenerator() const {return this->m_gpc.GetBase(this->GetGroupPrecomputation());}

	void SetModulusAndSubgroupGenerator(const Integer &p, const Integer &g)		// these have to be set together
		{this->m_groupPrecomputation.SetModulus(p); this->m_gpc.SetBase(this->GetGroupPrecomputation(), g); this->ParametersChanged();}

	// non-inherited
	bool operator==(const DL_GroupParameters_IntegerBasedImpl<GROUP_PRECOMP, BASE_PRECOMP> &rhs) const
		{return GetModulus() == rhs.GetModulus() && GetGenerator() == rhs.GetGenerator() && this->GetSubgroupOrder() == rhs.GetSubgroupOrder();}
	bool operator!=(const DL_GroupParameters_IntegerBasedImpl<GROUP_PRECOMP, BASE_PRECOMP> &rhs) const
		{return !operator==(rhs);}
};

CRYPTOPP_DLL_TEMPLATE_CLASS DL_GroupParameters_IntegerBasedImpl<ModExpPrecomputation>;

//! GF(p) group parameters
class CRYPTOPP_DLL DL_GroupParameters_GFP : public DL_GroupParameters_IntegerBasedImpl<ModExpPrecomputation>
{
public:
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_GFP() {}
#endif

	// DL_GroupParameters
	bool IsIdentity(const Integer &element) const {return element == Integer::One();}
	void SimultaneousExponentiate(Element *results, const Element &base, const Integer *exponents, unsigned int exponentsCount) const;

	// NameValuePairs interface
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
	{
		return GetValueHelper<DL_GroupParameters_IntegerBased>(this, name, valueType, pValue).Assignable();
	}

	// used by MQV
	Element MultiplyElements(const Element &a, const Element &b) const;
	Element CascadeExponentiate(const Element &element1, const Integer &exponent1, const Element &element2, const Integer &exponent2) const;

protected:
	int GetFieldType() const {return 1;}
};

//! GF(p) group parameters that default to same primes
class CRYPTOPP_DLL DL_GroupParameters_GFP_DefaultSafePrime : public DL_GroupParameters_GFP
{
public:
	typedef NoCofactorMultiplication DefaultCofactorOption;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_GFP_DefaultSafePrime() {}
#endif

protected:
	unsigned int GetDefaultSubgroupOrderSize(unsigned int modulusSize) const {return modulusSize-1;}
};

//! \class DL_Algorithm_GDSA
//! \brief Generalized DSA algorithm
//! \tparam T Field element
//! \details DL_Algorithm_GDSA() uses IEEE's P1363 algorithm, and StaticAlgorithmName() returns the string "DSA-1363".
template <class T>
class DL_Algorithm_GDSA : public DL_ElgamalLikeSignatureAlgorithm<T>
{
public:
	static const char * CRYPTOPP_API StaticAlgorithmName() {return "DSA-1363";}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Algorithm_GDSA() {}
#endif

	void Sign(const DL_GroupParameters<T> &params, const Integer &x, const Integer &k, const Integer &e, Integer &r, Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		r %= q;
		Integer kInv = k.InverseMod(q);
		s = (kInv * (x*r + e)) % q;
		assert(!!r && !!s);
	}

	bool Verify(const DL_GroupParameters<T> &params, const DL_PublicKey<T> &publicKey, const Integer &e, const Integer &r, const Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		if (r>=q || r<1 || s>=q || s<1)
			return false;

		Integer w = s.InverseMod(q);
		Integer u1 = (e * w) % q;
		Integer u2 = (r * w) % q;
		// verify r == (g^u1 * y^u2 mod p) mod q
		return r == params.ConvertElementToInteger(publicKey.CascadeExponentiateBaseAndPublicElement(u1, u2)) % q;
	}
};

//! \class DL_Algorithm_DSA_RFC6979
//! \brief DSA algorithm providing determinisitic signatures
//! \tparam T Field element
//! \tparam H Hash function
//! \details DL_Algorithm_DSA_RFC6979() uses IETF's algorithm, and StaticAlgorithmName() returns the string "DSA-RFC6979".
//! \sa <A HREF="http://tools.ietf.org/html/rfc6979">RFC 6979, Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)</A>
template <class T, class H>
class DL_Algorithm_DSA_RFC6979 : public DL_ElgamalLikeSignatureAlgorithm<T>
{
public:
	static const char * CRYPTOPP_API StaticAlgorithmName() { return "DSA-RFC6979";}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Algorithm_DSA_RFC6979() {}
#endif

	void Sign(const DL_GroupParameters<T> &params, const Integer &x, const Integer &k, const Integer &e, Integer &r, Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		r %= q;
		Integer kInv = k.InverseMod(q);
		s = (kInv * (x*r + e)) % q;
		assert(!!r && !!s);
	}

	bool Verify(const DL_GroupParameters<T> &params, const DL_PublicKey<T> &publicKey, const Integer &e, const Integer &r, const Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		if (r>=q || r<1 || s>=q || s<1)
			return false;

		Integer w = s.InverseMod(q);
		Integer u1 = (e * w) % q;
		Integer u2 = (r * w) % q;
		// verify r == (g^u1 * y^u2 mod p) mod q
		return r == params.ConvertElementToInteger(publicKey.CascadeExponentiateBaseAndPublicElement(u1, u2)) % q;
	}

	bool IsProbabilistic() const
	{
		return false;
	}

	void ComputeK(RandomNumberGenerator &rng, const DL_GroupParameters<T> &params, const Integer &x, const byte* encodedMsg, size_t encodedMsgLen, Integer &k) const
	{
		// Private key as a byte array
		SecByteBlock t(x.MinEncodedSize());
		x.Encode(t.begin(), t.size());

		// Step (a)
		SecByteBlock h1(H::DIGESTSIZE);
		m_hash.Update(encodedMsg, encodedMsgLen);
		m_hash.TruncatedFinal(h1, h1.size());

		// Step (b) and (c)
		static const SecByteBlock KK = CreateK();	// Create once
		static const SecByteBlock VV = CreateV();	// Create once
		static const byte zero[1] = { 0x00 };
		static const byte one[1] = { 0x01 };

		SecByteBlock K(HMAC<H>::DIGESTSIZE);
		SecByteBlock V(HMAC<H>::DIGESTSIZE);

		// Step (d)
		m_hmac.SetKey(KK.begin(), KK.size());
		m_hmac.Update(VV, VV.size());
		m_hmac.Update(zero, 1);
		m_hmac.Update(t.begin(), t.size());
		m_hmac.Update(encodedMsg, encodedMsgLen);
		m_hmac.TruncatedFinal(K.begin(), K.size());

		// Step (e)
		m_hmac.SetKey(K.begin(), K.size());
		m_hmac.Update(VV, VV.size());
		m_hmac.TruncatedFinal(V.begin(), V.size());

		// Step (f)
		m_hmac.SetKey(K.begin(), K.size());
		m_hmac.Update(V, V.size());
		m_hmac.Update(one, 1);
		m_hmac.Update(t.begin(), t.size());
		m_hmac.Update(encodedMsg, encodedMsgLen);
		m_hmac.TruncatedFinal(K.begin(), K.size());

		// Step (g)
		m_hmac.SetKey(K.begin(), K.size());
		m_hmac.Update(V, V.size());
		m_hmac.TruncatedFinal(V.begin(), V.size());

		// TODO: Step (h)
		Integer r(V.begin(), V.size());
		const size_t shift = SaturatingSubtract(m_hmac.DigestSize()*8, params.GetSubgroupOrder().BitCount());
		if (shift)
			r >>= shift;

		r.swap(k);
	}

	SecByteBlock CreateK() const
	{
		SecByteBlock K(HMAC<H>::DIGESTSIZE);
		std::fill(K.begin(), K.end(), byte(0x00));
		return K;
	}

	SecByteBlock CreateV() const
	{
		SecByteBlock V(HMAC<H>::DIGESTSIZE);
		std::fill(V.begin(), V.end(), byte(0x01));
		return V;
	}

private:
	mutable H m_hash;
	mutable HMAC<H> m_hmac;
};

CRYPTOPP_DLL_TEMPLATE_CLASS DL_Algorithm_GDSA<Integer>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_Algorithm_DSA_RFC6979<Integer, SHA256>;

//! NR algorithm
template <class T>
class DL_Algorithm_NR : public DL_ElgamalLikeSignatureAlgorithm<T>
{
public:
	static const char * CRYPTOPP_API StaticAlgorithmName() {return "NR";}

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Algorithm_NR() {}
#endif

	void Sign(const DL_GroupParameters<T> &params, const Integer &x, const Integer &k, const Integer &e, Integer &r, Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		r = (r + e) % q;
		s = (k - x*r) % q;
		assert(!!r);
	}

	bool Verify(const DL_GroupParameters<T> &params, const DL_PublicKey<T> &publicKey, const Integer &e, const Integer &r, const Integer &s) const
	{
		const Integer &q = params.GetSubgroupOrder();
		if (r>=q || r<1 || s>=q)
			return false;

		// check r == (m_g^s * m_y^r + m) mod m_q
		return r == (params.ConvertElementToInteger(publicKey.CascadeExponentiateBaseAndPublicElement(s, r)) + e) % q;
	}
};

/*! DSA public key format is defined in 7.3.3 of RFC 2459. The
	private key format is defined in 12.9 of PKCS #11 v2.10. */
template <class GP>
class DL_PublicKey_GFP : public DL_PublicKeyImpl<GP>
{
public:

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PublicKey_GFP() {}
#endif

	void Initialize(const DL_GroupParameters_IntegerBased &params, const Integer &y)
		{this->AccessGroupParameters().Initialize(params); this->SetPublicElement(y);}
	void Initialize(const Integer &p, const Integer &g, const Integer &y)
		{this->AccessGroupParameters().Initialize(p, g); this->SetPublicElement(y);}
	void Initialize(const Integer &p, const Integer &q, const Integer &g, const Integer &y)
		{this->AccessGroupParameters().Initialize(p, q, g); this->SetPublicElement(y);}

	// X509PublicKey
	void BERDecodePublicKey(BufferedTransformation &bt, bool, size_t)
		{this->SetPublicElement(Integer(bt));}
	void DEREncodePublicKey(BufferedTransformation &bt) const
		{this->GetPublicElement().DEREncode(bt);}
};

//! \brief Discrete logprivate key in GF(p) groups
//! \tparam GP Group parameters
template <class GP>
class DL_PrivateKey_GFP : public DL_PrivateKeyImpl<GP>
{
public:

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PrivateKey_GFP() {}
#endif

	void Initialize(RandomNumberGenerator &rng, unsigned int modulusBits)
		{this->GenerateRandomWithKeySize(rng, modulusBits);}
	void Initialize(RandomNumberGenerator &rng, const Integer &p, const Integer &g)
		{this->GenerateRandom(rng, MakeParameters("Modulus", p)("SubgroupGenerator", g));}
	void Initialize(RandomNumberGenerator &rng, const Integer &p, const Integer &q, const Integer &g)
		{this->GenerateRandom(rng, MakeParameters("Modulus", p)("SubgroupOrder", q)("SubgroupGenerator", g));}
	void Initialize(const DL_GroupParameters_IntegerBased &params, const Integer &x)
		{this->AccessGroupParameters().Initialize(params); this->SetPrivateExponent(x);}
	void Initialize(const Integer &p, const Integer &g, const Integer &x)
		{this->AccessGroupParameters().Initialize(p, g); this->SetPrivateExponent(x);}
	void Initialize(const Integer &p, const Integer &q, const Integer &g, const Integer &x)
		{this->AccessGroupParameters().Initialize(p, q, g); this->SetPrivateExponent(x);}
};

//! \brief Discrete log signing/verification keys in GF(p) groups
struct DL_SignatureKeys_GFP
{
	typedef DL_GroupParameters_GFP GroupParameters;
	typedef DL_PublicKey_GFP<GroupParameters> PublicKey;
	typedef DL_PrivateKey_GFP<GroupParameters> PrivateKey;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_SignatureKeys_GFP() {}
#endif
};

//! \brief Discrete log encryption/decryption keys in GF(p) groups
struct DL_CryptoKeys_GFP
{
	typedef DL_GroupParameters_GFP_DefaultSafePrime GroupParameters;
	typedef DL_PublicKey_GFP<GroupParameters> PublicKey;
	typedef DL_PrivateKey_GFP<GroupParameters> PrivateKey;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_CryptoKeys_GFP() {}
#endif
};

//! provided for backwards compatibility, this class uses the old non-standard Crypto++ key format
template <class BASE>
class DL_PublicKey_GFP_OldFormat : public BASE
{
public:

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PublicKey_GFP_OldFormat() {}
#endif

	void BERDecode(BufferedTransformation &bt)
	{
		BERSequenceDecoder seq(bt);
			Integer v1(seq);
			Integer v2(seq);
			Integer v3(seq);

			if (seq.EndReached())
			{
				this->AccessGroupParameters().Initialize(v1, v1/2, v2);
				this->SetPublicElement(v3);
			}
			else
			{
				Integer v4(seq);
				this->AccessGroupParameters().Initialize(v1, v2, v3);
				this->SetPublicElement(v4);
			}

		seq.MessageEnd();
	}

	void DEREncode(BufferedTransformation &bt) const
	{
		DERSequenceEncoder seq(bt);
			this->GetGroupParameters().GetModulus().DEREncode(seq);
			if (this->GetGroupParameters().GetCofactor() != 2)
				this->GetGroupParameters().GetSubgroupOrder().DEREncode(seq);
			this->GetGroupParameters().GetGenerator().DEREncode(seq);
			this->GetPublicElement().DEREncode(seq);
		seq.MessageEnd();
	}
};

//! provided for backwards compatibility, this class uses the old non-standard Crypto++ key format
template <class BASE>
class DL_PrivateKey_GFP_OldFormat : public BASE
{
public:

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_PrivateKey_GFP_OldFormat() {}
#endif

	void BERDecode(BufferedTransformation &bt)
	{
		BERSequenceDecoder seq(bt);
			Integer v1(seq);
			Integer v2(seq);
			Integer v3(seq);
			Integer v4(seq);

			if (seq.EndReached())
			{
				this->AccessGroupParameters().Initialize(v1, v1/2, v2);
				this->SetPrivateExponent(v4 % (v1/2));	// some old keys may have x >= q
			}
			else
			{
				Integer v5(seq);
				this->AccessGroupParameters().Initialize(v1, v2, v3);
				this->SetPrivateExponent(v5);
			}

		seq.MessageEnd();
	}

	void DEREncode(BufferedTransformation &bt) const
	{
		DERSequenceEncoder seq(bt);
			this->GetGroupParameters().GetModulus().DEREncode(seq);
			if (this->GetGroupParameters().GetCofactor() != 2)
				this->GetGroupParameters().GetSubgroupOrder().DEREncode(seq);
			this->GetGroupParameters().GetGenerator().DEREncode(seq);
			this->GetGroupParameters().ExponentiateBase(this->GetPrivateExponent()).DEREncode(seq);
			this->GetPrivateExponent().DEREncode(seq);
		seq.MessageEnd();
	}
};

//! \class GDSA
//! \brief Generalized DSA signature scheme
//! \sa <a href="http://www.weidai.com/scan-mirror/sig.html#DSA-1363">DSA-1363</a>
template <class H>
struct GDSA : public DL_SS<
	DL_SignatureKeys_GFP,
	DL_Algorithm_GDSA<Integer>,
	DL_SignatureMessageEncodingMethod_DSA,
	H>
{
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~GDSA() {}
#endif
};

//! \class DSA_RFC6979
//! \brief DSA deterministic signature scheme
//! \sa <a href="http://tools.ietf.org/rfc/rfc6979.txt">Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)</a>
template <class H>
struct DSA_RFC6979 : public DL_SS<
	DL_SignatureKeys_GFP,
	DL_Algorithm_DSA_RFC6979<Integer, H>,
	DL_SignatureMessageEncodingMethod_DSA,
	H>
{
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DSA_RFC6979() {}
#endif
};

//! \class NR
//! \brief Nyberg–Rueppel signature scheme
//! \sa <a href="http://www.weidai.com/scan-mirror/sig.html#NR">NR</a>
template <class H>
struct NR : public DL_SS<
	DL_SignatureKeys_GFP,
	DL_Algorithm_NR<Integer>,
	DL_SignatureMessageEncodingMethod_NR,
	H>
{
#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~NR() {}
#endif
};

//! DSA group parameters, these are GF(p) group parameters that are allowed by the DSA standard
class CRYPTOPP_DLL DL_GroupParameters_DSA : public DL_GroupParameters_GFP
{
public:

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_GroupParameters_DSA() {}
#endif

	/*! also checks that the lengths of p and q are allowed by the DSA standard */
	bool ValidateGroup(RandomNumberGenerator &rng, unsigned int level) const;
	/*! parameters: (ModulusSize), or (Modulus, SubgroupOrder, SubgroupGenerator) */
	/*! ModulusSize must be between DSA::MIN_PRIME_LENGTH and DSA::MAX_PRIME_LENGTH, and divisible by DSA::PRIME_LENGTH_MULTIPLE */
	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg);

	static bool CRYPTOPP_API IsValidPrimeLength(unsigned int pbits)
		{return pbits >= MIN_PRIME_LENGTH && pbits <= MAX_PRIME_LENGTH && pbits % PRIME_LENGTH_MULTIPLE == 0;}

	enum {MIN_PRIME_LENGTH = 1024, MAX_PRIME_LENGTH = 3072, PRIME_LENGTH_MULTIPLE = 1024};
};

template <class H>
class DSA2;

//! \brief DSA keys
struct DL_Keys_DSA
{
	typedef DL_PublicKey_GFP<DL_GroupParameters_DSA> PublicKey;
	typedef DL_PrivateKey_WithSignaturePairwiseConsistencyTest<DL_PrivateKey_GFP<DL_GroupParameters_DSA>, DSA2<SHA> > PrivateKey;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Keys_DSA() {}
#endif
};

//! \brief DSA-RFC6979 keys
struct DL_Keys_DSA_RFC6979
{
	typedef DL_PublicKey_GFP<DL_GroupParameters_DSA> PublicKey;
	typedef DL_PrivateKey_GFP<DL_GroupParameters_DSA> PrivateKey;

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_Keys_DSA_RFC6979() {}
#endif
};

//! <a href="http://en.wikipedia.org/wiki/Digital_Signature_Algorithm">DSA</a>, as specified in FIPS 186-3
// class named DSA2 instead of DSA for backwards compatibility (DSA was a non-template class)
template <class H>
class DSA2 : public DL_SS<
	DL_Keys_DSA,
	DL_Algorithm_GDSA<Integer>,
	DL_SignatureMessageEncodingMethod_DSA,
	H,
	DSA2<H> >
{
public:
	static std::string CRYPTOPP_API StaticAlgorithmName() {return "DSA/" + (std::string)H::StaticAlgorithmName();}

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
	enum {MIN_PRIME_LENGTH = 1024, MAX_PRIME_LENGTH = 3072, PRIME_LENGTH_MULTIPLE = 1024};
#endif

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DSA2() {}
#endif
};

template <class H>
class DSA2_RFC6979 : public DL_SS<
	DL_Keys_DSA_RFC6979,
	DL_Algorithm_DSA_RFC6979<Integer, H>,
	DL_SignatureMessageEncodingMethod_RFC6979,
	H,
	DSA2_RFC6979<H> >
{
public:
	static std::string CRYPTOPP_API StaticAlgorithmName() {return "DSA-RFC6979/" + (std::string)H::StaticAlgorithmName();}

#ifdef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
	enum {MIN_PRIME_LENGTH = 1024, MAX_PRIME_LENGTH = 3072, PRIME_LENGTH_MULTIPLE = 1024};
#endif

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DSA2_RFC6979() {}
#endif
};

//! DSA with SHA-1, typedef'd for backwards compatibility
typedef DSA2<SHA> DSA;

CRYPTOPP_DLL_TEMPLATE_CLASS DL_PublicKey_GFP<DL_GroupParameters_DSA>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKey_GFP<DL_GroupParameters_DSA>;
CRYPTOPP_DLL_TEMPLATE_CLASS DL_PrivateKey_WithSignaturePairwiseConsistencyTest<DL_PrivateKey_GFP<DL_GroupParameters_DSA>, DSA2<SHA> >;

//! the XOR encryption method, for use with DL-based cryptosystems
template <class MAC, bool DHAES_MODE>
class DL_EncryptionAlgorithm_Xor : public DL_SymmetricEncryptionAlgorithm
{
public:

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_EncryptionAlgorithm_Xor() {}
#endif

	bool ParameterSupported(const char *name) const {return strcmp(name, Name::EncodingParameters()) == 0;}
	size_t GetSymmetricKeyLength(size_t plaintextLength) const
		{return plaintextLength + MAC::DEFAULT_KEYLENGTH;}
	size_t GetSymmetricCiphertextLength(size_t plaintextLength) const
		{return plaintextLength + MAC::DIGESTSIZE;}
	size_t GetMaxSymmetricPlaintextLength(size_t ciphertextLength) const
		{return (unsigned int)SaturatingSubtract(ciphertextLength, (unsigned int)MAC::DIGESTSIZE);}
	void SymmetricEncrypt(RandomNumberGenerator &rng, const byte *key, const byte *plaintext, size_t plaintextLength, byte *ciphertext, const NameValuePairs &parameters) const
	{
		CRYPTOPP_UNUSED(rng);
		const byte *cipherKey = NULL, *macKey = NULL;
		if (DHAES_MODE)
		{
			macKey = key;
			cipherKey = key + MAC::DEFAULT_KEYLENGTH;
		}
		else
		{
			cipherKey = key;
			macKey = key + plaintextLength;
		}

		ConstByteArrayParameter encodingParameters;
		parameters.GetValue(Name::EncodingParameters(), encodingParameters);

		if (plaintextLength)	// Coverity finding
			xorbuf(ciphertext, plaintext, cipherKey, plaintextLength);

		MAC mac(macKey);
		mac.Update(ciphertext, plaintextLength);
		mac.Update(encodingParameters.begin(), encodingParameters.size());
		if (DHAES_MODE)
		{
			byte L[8] = {0,0,0,0};
			PutWord(false, BIG_ENDIAN_ORDER, L+4, word32(encodingParameters.size()));
			mac.Update(L, 8);
		}
		mac.Final(ciphertext + plaintextLength);
	}
	DecodingResult SymmetricDecrypt(const byte *key, const byte *ciphertext, size_t ciphertextLength, byte *plaintext, const NameValuePairs &parameters) const
	{
		size_t plaintextLength = GetMaxSymmetricPlaintextLength(ciphertextLength);
		const byte *cipherKey, *macKey;
		if (DHAES_MODE)
		{
			macKey = key;
			cipherKey = key + MAC::DEFAULT_KEYLENGTH;
		}
		else
		{
			cipherKey = key;
			macKey = key + plaintextLength;
		}

		ConstByteArrayParameter encodingParameters;
		parameters.GetValue(Name::EncodingParameters(), encodingParameters);

		MAC mac(macKey);
		mac.Update(ciphertext, plaintextLength);
		mac.Update(encodingParameters.begin(), encodingParameters.size());
		if (DHAES_MODE)
		{
			byte L[8] = {0,0,0,0};
			PutWord(false, BIG_ENDIAN_ORDER, L+4, word32(encodingParameters.size()));
			mac.Update(L, 8);
		}
		if (!mac.Verify(ciphertext + plaintextLength))
			return DecodingResult();

		if (plaintextLength)	// Coverity finding
			xorbuf(plaintext, ciphertext, cipherKey, plaintextLength);

		return DecodingResult(plaintextLength);
	}
};

//! _
template <class T, bool DHAES_MODE, class KDF>
class DL_KeyDerivationAlgorithm_P1363 : public DL_KeyDerivationAlgorithm<T>
{
public:

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DL_KeyDerivationAlgorithm_P1363() {}
#endif

	bool ParameterSupported(const char *name) const {return strcmp(name, Name::KeyDerivationParameters()) == 0;}
	void Derive(const DL_GroupParameters<T> &params, byte *derivedKey, size_t derivedLength, const T &agreedElement, const T &ephemeralPublicKey, const NameValuePairs &parameters) const
	{
		SecByteBlock agreedSecret;
		if (DHAES_MODE)
		{
			agreedSecret.New(params.GetEncodedElementSize(true) + params.GetEncodedElementSize(false));
			params.EncodeElement(true, ephemeralPublicKey, agreedSecret);
			params.EncodeElement(false, agreedElement, agreedSecret + params.GetEncodedElementSize(true));
		}
		else
		{
			agreedSecret.New(params.GetEncodedElementSize(false));
			params.EncodeElement(false, agreedElement, agreedSecret);
		}

		ConstByteArrayParameter derivationParameters;
		parameters.GetValue(Name::KeyDerivationParameters(), derivationParameters);
		KDF::DeriveKey(derivedKey, derivedLength, agreedSecret, agreedSecret.size(), derivationParameters.begin(), derivationParameters.size());
	}
};

//! Discrete Log Integrated Encryption Scheme, AKA <a href="http://www.weidai.com/scan-mirror/ca.html#DLIES">DLIES</a>
template <class COFACTOR_OPTION = NoCofactorMultiplication, bool DHAES_MODE = true>
struct DLIES
	: public DL_ES<
		DL_CryptoKeys_GFP,
		DL_KeyAgreementAlgorithm_DH<Integer, COFACTOR_OPTION>,
		DL_KeyDerivationAlgorithm_P1363<Integer, DHAES_MODE, P1363_KDF2<SHA1> >,
		DL_EncryptionAlgorithm_Xor<HMAC<SHA1>, DHAES_MODE>,
		DLIES<> >
{
	static std::string CRYPTOPP_API StaticAlgorithmName() {return "DLIES";}	// TODO: fix this after name is standardized

#ifndef CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY_562
	virtual ~DLIES() {}
#endif
};

NAMESPACE_END

#if CRYPTOPP_MSC_VERSION
# pragma warning(pop)
#endif

#endif
