#include <windows.h>
#include <cassert>
#include <cstdint>
#include <engextcpp.hpp>

#include "memscanslot.h"

namespace 
{
    void SwapEntries(ScanHitEntry* pArray, size_t indexA, size_t indexB)
    {
        ScanHitEntry temp = pArray[indexA];
        pArray[indexA] = pArray[indexB];
        pArray[indexB] = temp;
    }

    void Sort(ScanHitEntry* pArray, uint16_t startIndex, uint16_t endIndex)
    {
        assert(endIndex > startIndex);

        // Quadratic sort for now because I am lazy
        for (uint16_t i = startIndex; i < endIndex; ++i)
        {
            for (uint16_t j = i + 1; j <= endIndex; ++j)
            {
                if (pArray[i].pHitAddress > pArray[j].pHitAddress)
                {
                    SwapEntries(pArray, i, j);
                }
            }
        }
    }

    template<typename TScanType>
    bool Scan(TScanType* pMemStart, TScanType* pMemEnd, TScanType searchValue, MemScanSlot& slot, uint16_t* pNumEntriesOut)
    {
        assert(pNumEntriesOut);
        assert((reinterpret_cast<uintptr_t>(pMemStart) & (sizeof(TScanType) - 1)) == 0);

        const ULONG ScanSize = reinterpret_cast<uintptr_t>(pMemEnd) - reinterpret_cast<uintptr_t>(pMemStart);
        ExtRemoteData ScanSpace("ScanSpace", reinterpret_cast<ULONG64>(pMemStart), ScanSize);

        *pNumEntriesOut = 0;
        if (slot.GetSlotSize() != 0 && slot.GetSlotSize() != sizeof(TScanType))
        {
            // The search must match the current slot size, or the slot must be cleared. Otherwise, bail.
            return false;
        }

        ScanHitEntry* pEntries = slot.GetEntries();
        uint16_t numEntriesFound = 0;
        if (slot.GetNumEntries() > 0)
        {
            if (slot.GetNumEntries() > slot.GetMaxNumEntries())
            {
                // This is pretty unexpected!
                assert(false);
                return false;
            }

            // If there are any preexisting entries, we'll search within those results and ignore the start/end range.
            // Compact the array as we go and keep all valid entries from index zero upwards (if any still exists). Valid
            // entries are entries which have met all search criteria seen by this slot between clears.
            int16_t lastGoodIndex = static_cast<int16_t>(slot.GetNumEntries()) - 1;
            for (int16_t i = static_cast<int16_t>(slot.GetNumEntries()) - 1; i >= 0; --i)
            {
                ScanHitEntry& currentEntry = pEntries[i];
                assert(currentEntry.pHitAddress);

                ExtRemoteData EntryData(reinterpret_cast<ULONG64>(currentEntry.pHitAddress), sizeof(TScanType));
                const TScanType EntryValue = EntryData.GetData(sizeof(TScanType));
                if (EntryValue == searchValue)
                {
                    // Matching entry, we'll keep this one
                    ++numEntriesFound;

                    assert(numEntriesFound <= slot.GetNumEntries());
                }
                else
                {
                    assert(lastGoodIndex >= 0);

                    // Swap this invalid entry out and we'll sort later
                    SwapEntries(pEntries, lastGoodIndex, i);
                    lastGoodIndex--;
                }
            }

            if (numEntriesFound && numEntriesFound < slot.GetNumEntries())
            {
                Sort(pEntries, 0, numEntriesFound - 1);
            }
        }
        else
        {
            void* pLocalScanMemory = new uint8_t[ScanSize];
            TScanType* pLocalTypedArray = static_cast<TScanType*>(pLocalScanMemory);

            constexpr bool MustReadAll = true;
            const ULONG BytesRead = ScanSpace.ReadBuffer(pLocalScanMemory, ScanSize, MustReadAll);
            assert(BytesRead == ScanSize);

            size_t index = 0;
            size_t totalRead = 0;

            // Only used for tracking the original address and loop conditions,
            // don't directly read from the remote process address space!
            const size_t ElementsToScan = ScanSize / sizeof(TScanType);
            while (index < ElementsToScan)
            {
                if (pLocalTypedArray[index] == searchValue)
                {
                    pEntries[numEntriesFound].pHitAddress = pMemStart + index;
                    ++numEntriesFound;
                }

                if (numEntriesFound >= slot.GetMaxNumEntries())
                {
                    break;
                }
                ++index;
            }

            delete[] pLocalScanMemory;
        }

        *pNumEntriesOut = numEntriesFound;
        return true;
    }
}

MemScanSlot::MemScanSlot()
{
    Clear();
}

void MemScanSlot::Clear()
{
    m_slotSize = 0;
    m_numEntries = 0;
    ZeroMemory(m_scanEntries, sizeof(m_scanEntries));
}

bool MemScanSlot::ScanForByte(uint8_t* pMemStart, uint8_t* pMemEnd, uint8_t searchValue)
{
    uint16_t numEntriesFound = 0;
    if (!Scan(pMemStart, pMemEnd, searchValue, *this, &numEntriesFound))
    {
        return false;
    }

    m_numEntries = numEntriesFound;
    m_slotSize = 1;
    return true;
}

bool MemScanSlot::ScanForHalfWord(uint16_t* pMemStart, uint16_t* pMemEnd, uint16_t searchValue)
{
    uint16_t numEntriesFound = 0;
    if (!Scan(pMemStart, pMemEnd, searchValue, *this, &numEntriesFound))
    {
        return false;
    }

    m_numEntries = numEntriesFound;
    m_slotSize = 2;
    return true;
}

bool MemScanSlot::ScanForWord(uint32_t* pMemStart, uint32_t* pMemEnd, uint32_t searchValue)
{
    uint16_t numEntriesFound = 0;
    if (!Scan(pMemStart, pMemEnd, searchValue, *this, &numEntriesFound))
    {
        return false;
    }

    m_numEntries = numEntriesFound;
    m_slotSize = 4;
    return true;
}

uint8_t MemScanSlot::GetSlotSize() const
{
    return m_slotSize;
}

uint16_t MemScanSlot::GetNumEntries() const
{
    return m_numEntries;
}

uint16_t MemScanSlot::GetMaxNumEntries() const
{
    return kMaxNumEntries;
}

ScanHitEntry* MemScanSlot::GetEntries()
{
    return &m_scanEntries[0];
}

