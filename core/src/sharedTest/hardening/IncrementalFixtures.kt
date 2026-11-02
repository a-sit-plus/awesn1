// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.hardening

object IncrementalFixtures {
    val threeIntegers = "3009020101020102020103".hexToByteArray()
    val fourIntegers = "300c020101020102020103020104".hexToByteArray()
    val childBeyondParent = "3002020101".hexToByteArray()
}
