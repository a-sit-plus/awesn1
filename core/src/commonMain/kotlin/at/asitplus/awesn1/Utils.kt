// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

infix fun <T : Any> T?.orLazy(block: () -> T) =
    if (this != null) lazyOf(this) else lazy(block)
