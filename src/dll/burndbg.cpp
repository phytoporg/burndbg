//----------------------------------------------------------------------------
//
// burndbg.cpp
//
// EngExtCpp-style extension for NeoGeo game reverse engineering and debugging via
// the excellent FBNeo emulator.
//
// Author: Philippe Laurendeau
//
//----------------------------------------------------------------------------

#include <cassert>
#include <cstdint>

#include <engextcpp.hpp>
#include "memscanslot.h"

//----------------------------------------------------------------------------
// Constants yoinked from FBNeo.
//----------------------------------------------------------------------------
constexpr unsigned int SEK_SHIFT = 10;
constexpr unsigned int SEK_PAGE_SIZE = (1 << SEK_SHIFT);
constexpr unsigned int SEK_PAGE_MASK = SEK_PAGE_SIZE - 1;

//----------------------------------------------------------------------------
// Base extension class.
// Extensions derive from the provided ExtExtension class.
//----------------------------------------------------------------------------

class EXT_CLASS : public ExtExtension
{
public:
    EXT_COMMAND_METHOD(membase);
    EXT_COMMAND_METHOD(readb);
    EXT_COMMAND_METHOD(memscan);
    EXT_COMMAND_METHOD(slotclear);
    EXT_COMMAND_METHOD(slotinfo);
    EXT_COMMAND_METHOD(slotls);

private:
    // Helpers and such
    ExtRemoteTyped GetM68KRAMBase() const;
    ExtRemoteTyped GetM68KMemoryMap() const;

    // Memory scan slot data
    // A slot is either empty or contains some number of hits against a previous search
    static constexpr uint8_t kMaxMemScanSlots = 4;
    MemScanSlot m_scanSlots[kMaxMemScanSlots];

    void PrintSlot(uint16_t slotIndex);
};

// EXT_DECLARE_GLOBALS must be used to instantiate
// the framework's assumed globals.
EXT_DECLARE_GLOBALS();


//----------------------------------------------------------------------------
// 
// Private helper functions
// 
//----------------------------------------------------------------------------

ExtRemoteTyped EXT_CLASS::GetM68KRAMBase() const
{
    ExtRemoteTyped RamBase("fbneo64d_vs!Neo68KRAM");
    return RamBase;
}

ExtRemoteTyped EXT_CLASS::GetM68KMemoryMap() const
{
    ExtRemoteTyped SekExt("fbneo64d_vs!pSekExt");
    return SekExt.Dereference().Field("MemMap");
}

void EXT_CLASS::PrintSlot(uint16_t slotIndex)
{
    assert(slotIndex < kMaxMemScanSlots);

    MemScanSlot& Slot = m_scanSlots[slotIndex];
    if (Slot.GetNumEntries() == 0)
    {
        Out("Slot %d is clear\n", slotIndex);
    }
    else
    {
        Out("Slot %d:\n", slotIndex);

        const uint8_t SlotSize = Slot.GetSlotSize();
        ScanHitEntry* pEntries = Slot.GetEntries();
        for (uint16_t i = 0; i < Slot.GetNumEntries(); ++i)
        {
            const ScanHitEntry& Entry = pEntries[i];
            assert(Entry.pHitAddress);

            ExtRemoteData EntryData(reinterpret_cast<ULONG64>(Entry.pHitAddress), SlotSize);
            if (SlotSize == 1)
            {
                Out("%d:\t0x%p\t0x%02X\n", i, Entry.pHitAddress, EntryData.GetUchar());
            }
            else if (SlotSize == 2)
            {
                Out("%d:\t0x%p\t0x%04X\n", i, Entry.pHitAddress, EntryData.GetUshort());
            }
            else if (SlotSize == 4)
            {
                Out("%d:\t0x%p\t0x%08X\n", i, Entry.pHitAddress, EntryData.GetUlong());
            }
        }
        Out("Listed %d entries\n", Slot.GetNumEntries());
    }
}

//----------------------------------------------------------------------------
//
// membase extension command.
//
// Get the M68K RAM starting address in forreals host process space.
//
// Takes no argument.
//
//----------------------------------------------------------------------------
EXT_COMMAND(membase,
    "Get the base address in FBNeo for m68k RAM",NULL)
{
    Out("m68k RAM base: 0x%p\n", GetM68KRAMBase().GetPtr());
}

//----------------------------------------------------------------------------
//
// readb extension command.
//
// Read a byte from M68K memory.
//
// Argument is an expression which evaluates to a valid M68K address.
//
//----------------------------------------------------------------------------
EXT_COMMAND(readb,
    "Read a memory value from emulated m68K address space",
    "{;e,r;addr;Adress}")
{
    ExtRemoteTyped MemMap = GetM68KMemoryMap();
    const ULONG64 Address = GetUnnamedArgU64(0);

    // This is modeled after the implementation in FBNeo's ReadByte() in
    // m68000_intf.cpp.
    ExtRemoteTyped PR = MemMap.ArrayElement(Address >> SEK_SHIFT);
    const ULONG64 FlippedAddress = Address ^ 1;
    ExtRemoteTyped Value = PR.ArrayElement(FlippedAddress & SEK_PAGE_MASK);

    Out("$%06X = 0x%02X\n", Address, Value.GetUchar());
}

//----------------------------------------------------------------------------
//
// memscan extension command.
//
// TODO
//
//----------------------------------------------------------------------------
EXT_COMMAND(memscan,
    "Scan all of M68K RAM space and save the results to a slot, or scan against the resulting addresses already saved within a slot",
    "{;e,r;slot;TargetSlot}{;e,r;size;ValueSize}{;e,r;value;SearchValue}")
{
    const uint16_t SlotIndex = static_cast<uint16_t>(GetUnnamedArgU64(0));
    if (SlotIndex >= kMaxMemScanSlots)
    {
        Out("Target slot %d is out of bounds, only %d slots available\n",
            SlotIndex, kMaxMemScanSlots);
        return;
    }

    const uint8_t ValueSize = static_cast<uint8_t>(GetUnnamedArgU64(1));
    if (ValueSize != 1 && ValueSize != 2 && ValueSize != 4)
    {
        Out("Invalid search value size %d. Must be 1, 2 or 4\n", ValueSize);
        return;
    }

    const ULONG64 Value = GetUnnamedArgU64(2);
    MemScanSlot& targetSlot = m_scanSlots[SlotIndex];

    void* pMemStart = reinterpret_cast<void*>(GetM68KRAMBase().GetPtr());
    void* pMemEnd = static_cast<uint8_t*>(pMemStart) + 0x10000;
    bool success = true;
    if (ValueSize == 1)
    {
        success = 
            targetSlot.ScanForByte(
                static_cast<uint8_t*>(pMemStart), 
                static_cast<uint8_t*>(pMemEnd),
                Value & 0xFF);
    }
    else if (ValueSize == 2)
    {
        success = 
            targetSlot.ScanForHalfWord(
                static_cast<uint16_t*>(pMemStart), 
                static_cast<uint16_t*>(pMemEnd),
                Value & 0xFFFF);
    }
    else if (ValueSize == 4)
    {
        success = 
            targetSlot.ScanForWord(
                static_cast<uint32_t*>(pMemStart), 
                static_cast<uint32_t*>(pMemEnd),
                Value & 0xFFFFFFFF);
    }

    PrintSlot(SlotIndex);
}

EXT_COMMAND(slotclear,
    "Clear a memory scan slot",
    "{;e,r;slot;TargetSlot}")
{
    const uint16_t SlotIndex = static_cast<uint16_t>(GetUnnamedArgU64(0));
    if (SlotIndex >= kMaxMemScanSlots)
    {
        Out("Target slot %d is out of bounds, only %d slots available\n",
            SlotIndex, kMaxMemScanSlots);
        return;
    }

    MemScanSlot& targetSlot = m_scanSlots[SlotIndex];
    targetSlot.Clear();
    PrintSlot(SlotIndex);
}

EXT_COMMAND(slotinfo,
    "Dump info about a target memory scan slot",
    "{;e,r;slot;TargetSlot}")
{
    const uint16_t SlotIndex = static_cast<uint16_t>(GetUnnamedArgU64(0));
    if (SlotIndex >= kMaxMemScanSlots)
    {
        Out("Target slot %d is out of bounds, only %d slots available\n",
            SlotIndex, kMaxMemScanSlots);
        return;
    }

    PrintSlot(SlotIndex);
}

EXT_COMMAND(slotls,
    "List summary info about all memory scan slots",
    NULL)
{
    for (uint8_t i = 0; i < kMaxMemScanSlots; ++i)
    {
        const MemScanSlot& Slot = m_scanSlots[i];
        if (Slot.GetNumEntries() == 0)
        {
            Out("Slot %d: Clear\n", i);
        }
        else
        {
            Out("Slot %d: Size %u, %d hits\n",
                i, Slot.GetSlotSize(), Slot.GetNumEntries());
        }
    }
}
