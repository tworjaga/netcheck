package probe

import "strings"

// ouiTable maps the first three bytes of a MAC address to a vendor. It is a
// compact built-in subset of the IEEE registry covering routers, phones,
// TVs, speakers, printers and IoT gear commonly found at home; it is not the
// full list, so unknown prefixes simply show no vendor.
var ouiTable = map[string]string{
	// Apple
	"000393": "Apple", "000A95": "Apple", "000D93": "Apple", "001124": "Apple", "001451": "Apple",
	"0016CB": "Apple", "0017F2": "Apple", "0019E3": "Apple", "001B63": "Apple", "001CB3": "Apple",
	"001D4F": "Apple", "001E52": "Apple", "001EC2": "Apple", "001FF3": "Apple", "002241": "Apple",
	"002312": "Apple", "002332": "Apple", "00236C": "Apple", "0023DF": "Apple", "002436": "Apple",
	"002500": "Apple", "00254B": "Apple", "0025BC": "Apple", "002608": "Apple", "00264A": "Apple",
	"0026B0": "Apple", "0026BB": "Apple", "F01898": "Apple", "A45E60": "Apple", "3C0754": "Apple",
	"28CFE9": "Apple", "F0DBF8": "Apple", "D0034B": "Apple", "8C8590": "Apple", "A4B197": "Apple",
	// Raspberry Pi
	"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi", "28CDC1": "Raspberry Pi", "D83ADD": "Raspberry Pi",
	// Espressif (many smart plugs, bulbs and DIY sensors)
	"240AC4": "Espressif", "30AEA4": "Espressif", "840D8E": "Espressif", "A4CF12": "Espressif", "246F28": "Espressif",
	"7C9EBD": "Espressif", "3C71BF": "Espressif", "CC50E3": "Espressif", "ECFABC": "Espressif", "349454": "Espressif",
	// Amazon
	"74C246": "Amazon", "44650D": "Amazon", "F0272D": "Amazon", "6854FD": "Amazon", "FC65DE": "Amazon", "0C47C9": "Amazon",
	// Google / Nest
	"F4F5D8": "Google", "3C5AB4": "Google", "546009": "Google", "F88FCA": "Google", "A47733": "Google",
	// Samsung
	"001247": "Samsung", "0015B9": "Samsung", "001632": "Samsung", "0017C9": "Samsung", "001A8A": "Samsung",
	"002119": "Samsung", "5001BB": "Samsung", "8425DB": "Samsung", "FC1910": "Samsung",
	// TP-Link
	"50C7BF": "TP-Link", "F4F26D": "TP-Link", "14CC20": "TP-Link", "EC086B": "TP-Link", "98DAC4": "TP-Link",
	"30B5C2": "TP-Link", "A0F3C1": "TP-Link", "C006C3": "TP-Link",
	// Netgear
	"00095B": "Netgear", "00146C": "Netgear", "001B2F": "Netgear", "A06391": "Netgear", "9C3DCF": "Netgear",
	// AVM (Fritz!Box)
	"00040E": "AVM Fritz!Box", "3CA62F": "AVM Fritz!Box", "2C3AFD": "AVM Fritz!Box", "3810D5": "AVM Fritz!Box",
	"444E6D": "AVM Fritz!Box", "DC15C8": "AVM Fritz!Box", "C80E14": "AVM Fritz!Box", "3431C4": "AVM Fritz!Box",
	// Ubiquiti
	"002722": "Ubiquiti", "0418D6": "Ubiquiti", "24A43C": "Ubiquiti", "44D9E7": "Ubiquiti", "788A20": "Ubiquiti",
	"B4FBE4": "Ubiquiti", "DC9FDB": "Ubiquiti", "FCECDA": "Ubiquiti", "7483C2": "Ubiquiti", "802AA8": "Ubiquiti",
	// Sonos
	"000E58": "Sonos", "5CAAFD": "Sonos", "7828CA": "Sonos", "B8E937": "Sonos", "949F3E": "Sonos",
	// Philips Hue
	"001788": "Philips Hue",
	// Xiaomi
	"286C07": "Xiaomi", "34CE00": "Xiaomi", "50642B": "Xiaomi", "7811DC": "Xiaomi", "F8A45F": "Xiaomi",
	// Microsoft
	"0050F2": "Microsoft", "28186D": "Microsoft", "7C1E52": "Microsoft",
	// Sony
	"0013A9": "Sony", "001A80": "Sony", "FC0FE6": "Sony", "001D0D": "Sony",
	// LG
	"001C62": "LG", "001E75": "LG", "0022A9": "LG", "A8168D": "LG",
	// HP / Dell / Lenovo / Intel
	"001B78": "HP", "001871": "HP", "3C4A92": "HP", "001422": "Dell", "001A4B": "Dell", "F8BC12": "Dell",
	"00096B": "Lenovo", "28D244": "Lenovo", "001B21": "Intel", "3C970E": "Intel", "A4C3F0": "Intel",
	// Huawei
	"00E0FC": "Huawei", "286ED4": "Huawei", "00259E": "Huawei", "58BE35": "Huawei",
	// NAS, streaming, consoles, printers
	"001132": "Synology", "00089B": "QNAP", "B0A737": "Roku", "DC3A5E": "Roku",
	"0009BF": "Nintendo", "001656": "Nintendo", "0017AB": "Nintendo", "00191D": "Nintendo",
	"001599": "Canon", "00BBC1": "Canon", "0000F0": "Samsung", "008077": "Brother", "001BA9": "Brother",
	"002673": "Ricoh", "00001B": "Novell",
}

// Vendor returns the vendor for a MAC address, or "" if unknown.
func Vendor(mac string) string {
	h := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(h) < 6 {
		return ""
	}
	return ouiTable[h[:6]]
}

// IsRandomMAC reports whether a MAC has the "locally administered" bit set,
// which phones and laptops use for privacy-preserving random addresses.
// Such addresses carry no vendor information.
func IsRandomMAC(mac string) bool {
	h := strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac)
	if len(h) < 2 {
		return false
	}
	switch h[1] {
	case '2', '6', 'a', 'A', 'e', 'E':
		return true
	}
	return false
}
