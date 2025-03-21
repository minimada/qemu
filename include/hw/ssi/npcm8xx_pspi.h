/*
 * Nuvoton Peripheral SPI Module
 *
 * Copyright 2023 Google LLC
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */
#ifndef NPCM8XX_PSPI_H
#define NPCM8XX_PSPI_H

#include "hw/ssi/ssi.h"
#include "hw/sysbus.h"

/*
 * Number of registers in our device state structure. Don't change this without
 * incrementing the version_id in the vmstate.
 */
#define NPCM8XX_PSPI_NR_REGS 3

/**
 * NPCM8XXPSPIState - Device state for one Flash Interface Unit.
 * @parent: System bus device.
 * @mmio: Memory region for register access.
 * @spi: The SPI bus mastered by this controller.
 * @regs: Register contents.
 * @irq: The interrupt request queue for this module.
 *
 * Each PSPI has a shared bank of registers, and controls up to four chip
 * selects. Each chip select has a dedicated memory region which may be used to
 * read and write the flash connected to that chip select as if it were memory.
 */
typedef struct NPCM8XXPSPIState {
    SysBusDevice parent;

    MemoryRegion mmio;

    SSIBus *spi;
    uint16_t regs[NPCM8XX_PSPI_NR_REGS];
    qemu_irq irq;
} NPCM8XXPSPIState;

#define TYPE_NPCM8XX_PSPI "npcm8xx-pspi"
OBJECT_DECLARE_SIMPLE_TYPE(NPCM8XXPSPIState, NPCM8XX_PSPI)

#endif /* NPCM8XX_PSPI_H */
