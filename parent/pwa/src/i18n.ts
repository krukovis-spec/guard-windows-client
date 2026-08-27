import type { Language } from "./types";

const text = {
  ru: {
    product: "Guard · родитель", inbox: "Запросы", account: "Вход по ключу", loading: "Проверяем защищённые запросы…",
    offline: "Нет соединения", outage: "Во время сбоя действующие разрешения остаются на устройстве ребёнка; новые действия по умолчанию запрещены.",
    expired: "Срок запроса истёк", resolved: "Этот запрос уже решён", error: "Не удалось получить защищённые данные.",
    pending: "Ожидает решения", device: "Устройство", evidence: "Основание запроса", requested: "Запрошено",
    allowAlways: "Разрешить всегда", allowTemporary: "Разрешить на время", allowQuota: "Дневной лимит", deny: "Запретить",
    minutes: "Минуты", continuePhone: "Подтвердить на Android", copy: "Копировать ссылку", copied: "Ссылка скопирована", signIn: "Войти с ключом доступа", register: "Создать ключ доступа",
    open: "Открыть", noRequests: "Новых проверенных запросов нет.", language: "English", verified: "Проверено на устройстве"
  },
  en: {
    product: "Guard · parent", inbox: "Requests", account: "Passkey sign-in", loading: "Checking protected requests…",
    offline: "Connection unavailable", outage: "During an outage, existing grants remain local on the child device; new actions default to deny.",
    expired: "This request has expired", resolved: "This request has already been resolved", error: "Protected data could not be loaded.",
    pending: "Waiting for a decision", device: "Device", evidence: "Request evidence", requested: "Requested",
    allowAlways: "Allow always", allowTemporary: "Allow temporarily", allowQuota: "Daily allowance", deny: "Deny",
    minutes: "Minutes", continuePhone: "Confirm on Android", copy: "Copy link", copied: "Link copied", signIn: "Sign in with passkey", register: "Create passkey",
    open: "Open", noRequests: "No verified pending requests.", language: "Русский", verified: "Verified on device"
  }
} as const;

export type Copy = (typeof text)[Language];
export const copyFor = (language: Language): Copy => text[language];
