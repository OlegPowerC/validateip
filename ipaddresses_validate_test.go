package validateip

import "testing"

func TestCheckSingleIp(t *testing.T) {
	IpAddrs := []string{"192.168.0.7", "10.10.2.100", "128.0.7.1", "128.0.71", "0.240.1.7", "1025.33.55.77", "10.33.55.7f"}
	RetResult := CheckSingleIp(IpAddrs[0])
	if RetResult != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", RetResult)
	}
	RetResult = CheckSingleIp(IpAddrs[1])
	if RetResult != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", RetResult)
	}
	RetResult = CheckSingleIp(IpAddrs[2])
	if RetResult != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", RetResult)
	}
	RetResult = CheckSingleIp(IpAddrs[3])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	RetResult = CheckSingleIp(IpAddrs[4])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	RetResult = CheckSingleIp(IpAddrs[5])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	RetResult = CheckSingleIp(IpAddrs[6])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
}

func TestMakeListIPAddresses(t *testing.T) {
	IpAddrs := []string{"192.168.0.7-10", "10.10.2.100-120", "172.16.0.20", "128.0.7.1-257", "128.0.71-1f", "0.240.1.7-3", "10.240.1.7_3", "10.240,1.7-3", "10.240,1. 7-3", "10.240,1.7 -3", "10.240,1.7 - 3", "10.88.1.7-10,10.88.12.8"}

	IPList, RetResult := MakeListIPAddresses(IpAddrs[0])
	if RetResult != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", RetResult)
	} else {
		if len(IPList) != 4 {
			t.Error("Ожидается количество IP адресов 4 а получено:", len(IPList))
		}
	}
	IPList, RetResult = MakeListIPAddresses(IpAddrs[1])
	if RetResult != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", RetResult)
	} else {
		if len(IPList) != 21 {
			t.Error("Ожидается количество IP адресов 21 а получено:", len(IPList))
		}
	}
	IPList, RetResult = MakeListIPAddresses(IpAddrs[2])
	if RetResult != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", RetResult)
	} else {
		if len(IPList) != 1 {
			t.Error("Ожидается количество IP адресов 1 а получено:", len(IPList))
		}
	}
	IPList, RetResult = MakeListIPAddresses(IpAddrs[3])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddresses(IpAddrs[4])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddresses(IpAddrs[5])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddresses(IpAddrs[6])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddresses(IpAddrs[7])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddresses(IpAddrs[8])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddresses(IpAddrs[9])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddresses(IpAddrs[10])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}

	IPList, RetResult = MakeListIPAddresses(IpAddrs[11])
	if RetResult != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", RetResult)
	} else {
		if len(IPList) != 5 {
			t.Error("Ожидается количество IP адресов 5 а получено:", len(IPList))
		}
	}
}

func TestMakeListIPAddressesWithLoginPassword(t *testing.T) {
	IpAddrs := []string{"root:test123%a_123@192.168.0.7-10", "root:test:rrr@10.10.2.100-120", "root@172.16.0.20", "128.0.7.1-257", "128.0.71-1f", "0.240.1.7-3", "10.240.1.7_3", "10.240,1.7-3", "10.240,1. 7-3", "10.240,1.7 -3", "10.240,1.7 - 3", "10.88.1.7-10,10.88.12.8"}

	IPList, RetResult := MakeListIPAddressesWithLoginPassword(IpAddrs[0])
	if RetResult != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", RetResult)
	} else {
		if len(IPList) != 4 {
			t.Error("Ожидается количество IP адресов 4 а получено:", len(IPList))
		}
		for _, rdata := range IPList {
			if rdata.Login != "root" {
				t.Error("Ожидается имя пользователя root а получено", rdata.Login)
			}
			if rdata.Password != "test123%a_123" {
				t.Error("Ожидается пароль test123%a_123 а получен", rdata.Password)
			}
		}
	}
	IPList, RetResult = MakeListIPAddressesWithLoginPassword(IpAddrs[1])
	if RetResult == nil {
		t.Error("Ожидается ошибка Invalid IP user password ipaddress string")
	}

	IPList, RetResult = MakeListIPAddressesWithLoginPassword(IpAddrs[2])
	if RetResult == nil {
		t.Error("Ожидается ошибка Invalid IP user password ipaddress string")
	}
	IPList, RetResult = MakeListIPAddressesWithLoginPassword(IpAddrs[3])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddressesWithLoginPassword(IpAddrs[4])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddressesWithLoginPassword(IpAddrs[5])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddressesWithLoginPassword(IpAddrs[6])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddressesWithLoginPassword(IpAddrs[7])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddressesWithLoginPassword(IpAddrs[8])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddressesWithLoginPassword(IpAddrs[9])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}
	IPList, RetResult = MakeListIPAddressesWithLoginPassword(IpAddrs[10])
	if RetResult == nil {
		t.Error("Ожидается ошибка")
	}

	IPList, RetResult = MakeListIPAddressesWithLoginPassword(IpAddrs[11])
	if RetResult != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", RetResult)
	} else {
		if len(IPList) != 5 {
			t.Error("Ожидается количество IP адресов 5 а получено:", len(IPList))
		}
	}
}
