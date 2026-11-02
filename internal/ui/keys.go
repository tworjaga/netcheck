package ui

// Key is a decoded key press, identical on every OS so the menu logic is
// shared and testable.
type Key int

const (
	KeyNone Key = iota // read timed out; nothing pressed
	KeyUp
	KeyDown
	KeyEnter
	KeyEsc
	KeyCtrlC
	KeyBackspace
	KeyRune
	KeyTab
)

// KeyEvent is one key press. Rune is set when Key is KeyRune.
type KeyEvent struct {
	Key  Key
	Rune rune
}

// parseKey decodes a byte stream (Unix terminals) into a key event. read
// returns false when the read timed out, which is how a bare Esc is told
// apart from an arrow-key sequence.
func parseKey(read func() (byte, bool)) KeyEvent {
	b, ok := read()
	if !ok {
		return KeyEvent{}
	}
	switch {
	case b == 3:
		return KeyEvent{Key: KeyCtrlC}
	case b == '\r' || b == '\n':
		return KeyEvent{Key: KeyEnter}
	case b == '\t':
		return KeyEvent{Key: KeyTab}
	case b == 127 || b == 8:
		return KeyEvent{Key: KeyBackspace}
	case b == 0x1b:
		b2, ok := read()
		if !ok {
			return KeyEvent{Key: KeyEsc}
		}
		if b2 != '[' && b2 != 'O' {
			return KeyEvent{}
		}
		for i := 0; i < 8; i++ { // skip parameters like "1;5" until the final byte
			c, ok := read()
			if !ok {
				return KeyEvent{}
			}
			switch c {
			case 'A':
				return KeyEvent{Key: KeyUp}
			case 'B':
				return KeyEvent{Key: KeyDown}
			}
			if c >= '@' && c <= '~' {
				return KeyEvent{}
			}
		}
	case b >= 32 && b < 127:
		return KeyEvent{Key: KeyRune, Rune: rune(b)}
	}
	return KeyEvent{}
}

// Windows console virtual-key codes and modifier bits. They live here, not
// in the Windows-only file, so the mapping is unit-tested on every OS.
const (
	vkBack          = 0x08
	vkTab           = 0x09
	vkReturn        = 0x0D
	vkEscape        = 0x1B
	vkUp            = 0x26
	vkDown          = 0x28
	vkC             = 0x43
	ctrlPressedMask = 0x0008 | 0x0004 // LEFT_CTRL | RIGHT_CTRL
)

// translateKey maps a Windows console key event onto the shared key set.
func translateKey(vk, ch uint16, ctrl uint32) KeyEvent {
	switch {
	case ch == 3 || (vk == vkC && ctrl&ctrlPressedMask != 0):
		return KeyEvent{Key: KeyCtrlC}
	case vk == vkUp:
		return KeyEvent{Key: KeyUp}
	case vk == vkDown:
		return KeyEvent{Key: KeyDown}
	case vk == vkReturn:
		return KeyEvent{Key: KeyEnter}
	case vk == vkEscape:
		return KeyEvent{Key: KeyEsc}
	case vk == vkTab:
		return KeyEvent{Key: KeyTab}
	case vk == vkBack:
		return KeyEvent{Key: KeyBackspace}
	case ch >= 32 && ch != 127:
		return KeyEvent{Key: KeyRune, Rune: rune(ch)}
	}
	return KeyEvent{}
}
