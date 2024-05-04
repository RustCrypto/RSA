#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]

extern crate alloc;

use cmpv2::status::PkiStatusInfo;
use cms::content_info::ContentInfo;
use der::{
    asn1::{GeneralizedTime, Int, OctetString},
    oid::ObjectIdentifier,
    Any, Enumerated, Sequence,
};
use x509_cert::{
    ext::{pkix::name::GeneralName, Extensions},
    spki::AlgorithmIdentifier,
};

#[derive(Clone, Copy, Debug, Enumerated, Eq, PartialEq, PartialOrd, Ord)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum TspVersion {
    /// syntax version 0
    V1 = 1,
}

/// ```text
/// TimeStampReq ::= SEQUENCE  {
///    version               INTEGER  { v1(1) },
///    messageImprint        MessageImprint,
///    reqPolicy             TSAPolicyId              OPTIONAL,
///    nonce                 INTEGER                  OPTIONAL,
///    certReq               BOOLEAN                  DEFAULT FALSE,
///    extensions            [0] IMPLICIT Extensions  OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampReq {
    pub version: TspVersion,
    pub message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    pub req_policy: Option<TsaPolicyId>,
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    #[asn1(default = "Default::default")]
    pub cert_req: bool,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}

/// ```text
/// TSAPolicyId ::= OBJECT IDENTIFIER
/// ```
pub type TsaPolicyId = ObjectIdentifier;

/// ```text
/// MessageImprint ::= SEQUENCE  {
///    hashAlgorithm                AlgorithmIdentifier,
///    hashedMessage                OCTET STRING  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifier<Any>,
    pub hashed_message: OctetString,
}

/// ```text
/// TimeStampResp ::= SEQUENCE  {
///     status                  PKIStatusInfo,
///     timeStampToken          TimeStampToken     OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampResp<'a> {
    pub status: PkiStatusInfo<'a>,
    #[asn1(optional = "true")]
    pub time_stamp_token: Option<TimeStampToken>,
}

/// ```text
/// TimeStampToken ::= ContentInfo
/// ```
pub type TimeStampToken = ContentInfo;

/// ```text
/// TSTInfo ::= SEQUENCE  {
///     version                      INTEGER  { v1(1) },
///     policy                       TSAPolicyId,
///     messageImprint               MessageImprint,
///       -- MUST have the same value as the similar field in
///       -- TimeStampReq
///     serialNumber                 INTEGER,
///       -- Time-Stamping users MUST be ready to accommodate integers
///       -- up to 160 bits.
///     genTime                      GeneralizedTime,
///     accuracy                     Accuracy                 OPTIONAL,
///     ordering                     BOOLEAN             DEFAULT FALSE,
///     nonce                        INTEGER                  OPTIONAL,
///       -- MUST be present if the similar field was present
///       -- in TimeStampReq.  In that case it MUST have the same value.
///     tsa                          [0] GeneralName          OPTIONAL,
///     extensions                   [1] IMPLICIT Extensions   OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TstInfo {
    pub version: TspVersion,
    pub policy: TsaPolicyId,
    pub message_imprint: MessageImprint,
    pub serial_number: Int,
    pub gen_time: GeneralizedTime,
    #[asn1(optional = "true")]
    pub accuracy: Option<Accuracy>,
    #[asn1(default = "Default::default")]
    pub ordering: bool,
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub tsa: Option<GeneralName>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}

/// ```text
/// Accuracy ::= SEQUENCE {
///     seconds        INTEGER              OPTIONAL,
///     millis     [0] INTEGER  (1..999)    OPTIONAL,
///     micros     [1] INTEGER  (1..999)    OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Accuracy {
    #[asn1(optional = "true")]
    pub seconds: Option<u64>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub millis: Option<i16>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub micros: Option<i16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use cmpv2::status::*;
    use cms::signed_data::SignedData;
    use der::oid::db::rfc5912::ID_SHA_256;
    use der::{Decode, Encode};
    use hex_literal::hex;

    // Tests use keys generated via openssl as follows:
    //  openssl ecparam -genkey -name secp384r1 -noout -out ec384-tsa-key.pem
    //  openssl req -new -key ec384-tsa-key.pem -out ec384-tsa-key.csr -addext "extendedKeyUsage = critical, timeStamping"
    //  openssl req -text -in ec384-tsa-key.csr -noout
    //  openssl x509 -req -days 365 -in ec384-tsa-key.csr -signkey ec384-tsa-key.pem -out ec384-tsa-key.crt -copy_extensions copyall

    // The following config file contributes TSA-related settings in tsa.cnf:
    // [ tsa ]
    // default_tsa = tsa_config1	# the default TSA section
    //
    // [ tsa_config1 ]
    // # These are used by the TSA reply generation only.
    // dir		= ./		# TSA root directory
    // serial		= $dir/tsaserial	# The current serial number (mandatory)
    // crypto_device	= builtin		# OpenSSL engine to use for signing
    // signer_cert	= $dir/ec384-tsa-key.crt 	# The TSA signing certificate
    // 					# (optional)
    // certs		= $dir/ec384-tsa-key.crt	# Certificate chain to include in reply
    // 					# (optional)
    // signer_key	= $dir/ec384-tsa-key.pem # The TSA private key (optional)
    // signer_digest  = sha256			# Signing digest to use. (Optional)
    // default_policy	= 1.2.3.4.1		# Policy if request did not specify it
    // 					# (optional)
    // other_policies	= 1.2.3.4.5.6, 1.2.3.4.5.7	# acceptable policies (optional)
    // digests     = sha1, sha256, sha384, sha512  # Acceptable message digests (mandatory)
    // accuracy	= secs:1, millisecs:500, microsecs:100	# (optional)
    // clock_precision_digits  = 0	# number of digits after dot. (optional)
    // ordering		= yes	# Is ordering defined for timestamps?
    // 				# (optional, default: no)
    // tsa_name		= yes	# Must the TSA name be included in the reply?
    // 				# (optional, default: no)
    // ess_cert_id_chain	= no	# Must the ESS cert id chain be included?
    // 				# (optional, default: no)
    // ess_cert_id_alg		= sha1	# algorithm to compute certificate
    // 				# identifier (optional, default: sha1)

    #[test]
    fn request_test() {
        // openssl ts --query --data abc.txt -out query.tsq
        let enc_req = hex!("30400201013031300D060960864801650304020105000420BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD0208314CFCE4E0651827");
        let req = TimeStampReq::from_der(&enc_req).unwrap();
        assert_eq!(req.version, TspVersion::V1);
        assert_eq!(req.message_imprint.hash_algorithm.oid, ID_SHA_256);
        assert_eq!(
            req.message_imprint.hashed_message.as_bytes(),
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(req.nonce.unwrap().as_bytes(), hex!("314CFCE4E0651827"));
    }
    #[test]
    fn response_test() {
        // openssl ts -reply -queryfile query.tsq -signer ec384-tsa-key.crt -inkey ec384-tsa-key.pem -out response.tsr -config tsa.cnf
        let enc_resp = hex!("3082028430030201003082027B06092A864886F70D010702A082026C30820268020103310F300D060960864801650304020105003081C9060B2A864886F70D0109100104A081B90481B63081B302010106042A0304013031300D060960864801650304020105000420BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD020104180F32303233303630373131323632365A300A020101800201F48101640101FF0208314CFCE4E0651827A048A4463044310B30090603550406130255533113301106035504080C0A536F6D652D5374617465310D300B060355040A0C04546573743111300F06035504030C0854657374205453413182018430820180020101305C3044310B30090603550406130255533113301106035504080C0A536F6D652D5374617465310D300B060355040A0C04546573743111300F06035504030C08546573742054534102146A0DCC59137C11D1C2B092042B4BC51C0D634D24300D06096086480165030402010500A08198301A06092A864886F70D010903310D060B2A864886F70D0109100104301C06092A864886F70D010905310F170D3233303630373131323632365A302B060B2A864886F70D010910020C311C301A3018301604142F36B1B52456F5AC3A1CA09794AE3D0D64AD38C2302F06092A864886F70D01090431220420BAF4CCF82E9B5B3956EADCC87346B407684F26D82B68D0E7DE0D31EA79AF648C300A06082A8648CE3D0403020467306502305A6E1C175B20A93FAB25D14CC5F5A2836D726D6D4A964B66FFBFFCE46276A96475F1408728B3385DCA37C2BA46BE17E1023100C46B7F08D03409A8ECCFD7637765412C3C5EC050E0D39CF48F0F5015950342CB18D8434FF331BA4463C086297C37D07B");
        let resp = TimeStampResp::from_der(&enc_resp).unwrap();
        let content = resp.time_stamp_token.unwrap().content;
        let sd = SignedData::from_der(&content.to_der().unwrap()).unwrap();
        let encap = sd.encap_content_info.econtent.unwrap();
        let tst = TstInfo::from_der(&encap.value()).unwrap();
        assert_eq!(resp.status.status, PkiStatus::Accepted);
        assert_eq!(tst.version, TspVersion::V1);
        assert_eq!(tst.policy.to_string(), "1.2.3.4.1");
        assert_eq!(tst.message_imprint.hash_algorithm.oid, ID_SHA_256);
        assert_eq!(tst.serial_number.as_bytes(), hex!("04"));
        assert_eq!(tst.gen_time.to_unix_duration().as_secs(), 1686137186);
        let accuracy = tst.accuracy.unwrap();
        assert_eq!(accuracy.seconds.unwrap(), 1);
        assert_eq!(accuracy.millis.unwrap(), 500);
        assert_eq!(accuracy.micros.unwrap(), 100);
        assert!(tst.ordering);
        assert_eq!(tst.nonce.unwrap().as_bytes(), hex!("314CFCE4E0651827"));
        let gn = tst.tsa.unwrap();
        let dn = match gn {
            GeneralName::DirectoryName(n) => n,
            _ => panic!(),
        };
        assert_eq!(dn.to_string(), "CN=Test TSA,O=Test,ST=Some-State,C=US");
        assert_eq!(
            tst.message_imprint.hashed_message.as_bytes(),
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert!(tst.extensions.is_none());
    }
}
