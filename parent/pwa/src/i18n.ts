import type { Language } from "./types";

const text = {
  ru: {
    product: "Guard · родитель", inbox: "Запросы", account: "Вход по ключу", loading: "Проверяем защищённые запросы…",
    offline: "Нет соединения", outage: "Кабинет не подтверждает, что защита на компьютере ребёнка включена. Вход в кабинет сам по себе не выдаёт разрешений.",
    development: "Версия для разработки — не готова для защиты ребёнка",
    developmentDetail: "Связь с компьютером и подтверждение отпечатком пальца ещё не соединены в рабочий сценарий. Не устанавливайте текущую сборку на детский компьютер.",
    notConfigured: "Проверка запросов ещё не подключена",
    accountUnavailable: "Вход и создание ключа недоступны, пока не подключена безопасная проверка запросов.",
    expired: "Срок запроса истёк", resolved: "Этот запрос уже решён", error: "Не удалось получить защищённые данные.",
    pending: "Ожидает решения", device: "Устройство", evidence: "Основание запроса", requested: "Запрошено",
    allowAlways: "Разрешить всегда", allowTemporary: "Разрешить на время", allowQuota: "Дневной лимит", deny: "Запретить",
    minutes: "Минуты", continuePhone: "Подтвердить на Android", copy: "Копировать ссылку", copied: "Ссылка скопирована", signIn: "Войти с ключом доступа", register: "Создать ключ доступа",
    open: "Открыть", noRequests: "Новых проверенных запросов нет.", language: "Английский", verified: "Список запросов получен"
  },
  en: {
    product: "Guard · parent", inbox: "Requests", account: "Passkey sign-in", loading: "Checking protected requests…",
    offline: "Connection unavailable", outage: "This cabinet does not confirm that protection is enabled on the child computer. Signing in does not grant access.",
    development: "Development version — not ready to protect a child",
    developmentDetail: "Computer connectivity and fingerprint approval are not yet connected end to end. Do not install this build on a child computer.",
    notConfigured: "Request verification is not connected yet",
    accountUnavailable: "Sign-in and key registration are unavailable until secure request verification is connected.",
    expired: "This request has expired", resolved: "This request has already been resolved", error: "Protected data could not be loaded.",
    pending: "Waiting for a decision", device: "Device", evidence: "Request evidence", requested: "Requested",
    allowAlways: "Allow always", allowTemporary: "Allow temporarily", allowQuota: "Daily allowance", deny: "Deny",
    minutes: "Minutes", continuePhone: "Confirm on Android", copy: "Copy link", copied: "Link copied", signIn: "Sign in with passkey", register: "Create passkey",
    open: "Open", noRequests: "No verified pending requests.", language: "Русский", verified: "Request list received"
  }
} as const;

export type Copy = (typeof text)[Language];
export const copyFor = (language: Language): Copy => text[language];
