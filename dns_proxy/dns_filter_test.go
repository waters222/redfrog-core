package dns_proxy

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

type testCase struct {
	input        []byte
	verification []byte
}

func TestFilterComment(t *testing.T) {

	lines := []testCase{
		testCase{[]byte("### 测试1"), []byte("")},
		testCase{[]byte("#测试2 ###"), []byte("")},
		testCase{[]byte("测试3 # 哈哈##"), []byte("测试3 ")},
		testCase{[]byte("hi there"), []byte("hi there")},
	}
	for _, line := range lines {
		filtered := filterComment(line.input)
		if bytes.Compare(line.verification, filtered) != 0 {
			t.Errorf("filter comment failed: output: %s != verification: %s", filtered, line.verification)
			t.Fail()
		}
	}
}

func TestDomainExtraction(t *testing.T) {
	temp := make([]string, 128)
	for i := 0; i < 128; i++ {
		temp[i] = strconv.Itoa(i)
	}
	deepSubDomains := strings.Join(temp, ".")
	deepSubDomains = deepSubDomains + ".com"
	domains := []testCase{
		testCase{[]byte("www.google.com"), []byte("www.google.com")},
		testCase{[]byte("google.com"), []byte("google.com")},
		testCase{[]byte("google.ca"), []byte("google.ca")},
		testCase{[]byte("测试1.com"), []byte("测试1.com")},
		testCase{[]byte("xn--masekowski-d0b.pl"), []byte("xn--masekowski-d0b.pl")},
		testCase{[]byte("中国互联网络信息中心.中国"), []byte("中国互联网络信息中心.中国")},
		testCase{[]byte("中国互联网络信息中心.com"), []byte("中国互联网络信息中心.com")},
		testCase{[]byte("com.中国"), []byte("com.中国")},
		testCase{[]byte("中国.com.中国"), []byte("中国.com.中国")},
		testCase{[]byte("xn--fiqa61au8b7zsevnm8ak20mc4a87e.xn--fiqs8s"), []byte("xn--fiqa61au8b7zsevnm8ak20mc4a87e.xn--fiqs8s")},
		testCase{[]byte("cn"), nil},
		testCase{[]byte("  岡山.jp  "), []byte("岡山.jp")},
		testCase{[]byte("  哈哈.com  "), []byte("哈哈.com")},
		testCase{[]byte("  2哈哈2.com  "), []byte("2哈哈2.com")},
		testCase{[]byte("  3哈哈.com#测试aa.com  "), []byte("3哈哈.com")},
		testCase{[]byte("1234567890.com"), []byte("1234567890.com")},
		testCase{[]byte("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890.com"), nil},
		testCase{[]byte("1234567890.12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"), nil},
		testCase{[]byte("# [http://play.google.com/store/apps/details?id=com.coconuts.webnavigator]"), nil},
		testCase{[]byte("127.0.0.1 ads.adadapted.com"), []byte("ads.adadapted.com")},
		testCase{[]byte("lalala..com"), nil},
		testCase{[]byte("lalala.com."), nil},
		testCase{[]byte(".lalala.com."), nil},
		testCase{[]byte("  éexample.comé   "), []byte("éexample.comé")},
		testCase{[]byte("1.2.3.4.5.6.7.8.9.10.com"), []byte("1.2.3.4.5.6.7.8.9.10.com")},
		testCase{[]byte(deepSubDomains[:]), nil},
	}

	for _, domain := range domains {
		filtered := filterComment(domain.input)
		if extracted, err := extractDomain(filtered); err != nil {
			t.Errorf("extract domain failed from {%s}: %s", domain.input, err.Error())
			t.Fail()
		} else if bytes.Compare(domain.verification, extracted) != 0 {
			t.Errorf("extract domain failed from: {%s}\noutput: {%s} != verification: {%s}", domain.input, extracted, domain.verification)
			t.Fail()
		}
	}
}
