#include <windows.h>
#include <cassert>
#include <cstdint>

#include "memscanslot.h"

// TODO: REMOVE
#include <engextcpp.hpp>
// TODO: REMOVE

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
            uint16_t lastGoodIndex = slot.GetNumEntries() - 1;
            for (uint16_t i = slot.GetNumEntries() - 1; i >= 0; --i)
            {
                ScanHitEntry& currentEntry = pEntries[i];
                assert(currentEntry.pHitAddress);

                if (*static_cast<TScanType*>(currentEntry.pHitAddress) == searchValue)
                {
                    // Matching entry, we'll keep this one
                    ++numEntriesFound;

                    assert(numEntriesFound <= slot.GetNumEntries());
                }
                else
                {
                    assert(lastGoodIndex > 0);

                    // Swap this invalid entry out and we'll sort later
                    SwapEntries(pEntries, lastGoodIndex, i);
                    lastGoodIndex--;
                }
            }

            if (numEntriesFound && numEntriesFound < slot.GetNumEntries())
            {
                Sort(pEntries, 0, numEntriesFound);
            }
        }
        else
        {
            // We should not have any active entries at this point
            assert(slot.GetNumEntries() == 0);

            TScanType* pSearch = pMemStart;
            while (pSearch != pMemEnd)
            {
                if (*pSearch == searchValue)
                {
                    pEntries[slot.GetNumEntries()].pHitAddress = pSearch;
                    ++numEntriesFound;
                }

                if (numEntriesFound >= slot.GetMaxNumEntries())
                {
                    break;
                }
                ++pSearch;
            }
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

