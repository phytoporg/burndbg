#pragma once

#include <cstdint>

struct ScanHitEntry
{
    void* pHitAddress = nullptr;
};

class MemScanSlot
{
public:
    MemScanSlot();

    void Clear();

    // These all assume that the caller has already aligned pMemStart according to
    // the search type
    bool ScanForByte(uint8_t* pMemStart, uint8_t* pMemEnd, uint8_t searchValue);
    bool ScanForHalfWord(uint16_t* pMemStart, uint16_t* pMemEnd, uint16_t searchValue);
    bool ScanForWord(uint32_t* pMemStart, uint32_t* pMemEnd, uint32_t searchValue);

    uint8_t GetSlotSize() const;
    uint16_t GetNumEntries() const;
    uint16_t GetMaxNumEntries() const;
    ScanHitEntry* GetEntries();

private:
    // The size of the active scan
    uint8_t m_slotSize = 0;

    static constexpr uint16_t kMaxNumEntries = 0x1000;
    ScanHitEntry m_scanEntries[kMaxNumEntries];
    uint16_t m_numEntries = 0;
};