// API client for MIREA backend
const API_BASE_URL = "https://t-mirea.ru/api"

export interface User {
  id: string
  telegram_id: number
  email: string
  fullname: string
  group: string
  custom_proxy?: string
  has_totp_secret?: boolean
  created_at: number
  updated_at: number
}

export interface ApiResponse<T> {
  data: T
  paging?: any
  errors?: string
}

export interface SignUpRequest {
  email: string
  password: string
  otp_code?: string 
  miniAppUser?: string
  webAppUser?: {
    id: number
    first_name: string
    last_name?: string
    username?: string
  }
}

export interface ChangePasswordRequest {
  new_password: string
}

export interface UpdateProxyRequest {
  proxy: string
}

export interface UpdateTotpSecretRequest {
  totp_secret: string
}

export interface DisciplineScoreData {
  title: string
  now: number
  max: number
}

export interface Discipline {
  title: string
  total: number
  avg_group: number
  score_data?: DisciplineScoreData[]
}

export interface DisciplinesResponse {
  count_students: number
  disciplines: Discipline[]
}

export interface Student {
  email: string
  fullname: string
  group: string
  enabled?: boolean
}

export interface Lesson {
  uuid: string
  auditorium: string
  campus: string
  title: string
  type: string
  start: number
  end: number
  teacher: string
  groups: string[]
  attended: number
  total: number
  status: number
}

export interface AttendanceRecord {
  fullname: string
  status: number
  is_elder: boolean
}

export interface ScanQrResponse {
  students: Record<string, number>
  subject: string
}

export interface BypassStatus {
  status: boolean
  time: number
}

export interface UniversityEventDetail {
  time: number
  entry_location: string
  exit_location: string
  is_entry: boolean
}

export interface UniversityStatus {
  is_in_university: boolean
  entry_time?: number
  exit_time?: number
  events?: UniversityEventDetail[]
}

export interface Deadline {
  title: string
  timestamp: number
  subject: string
}

export interface AdminStats {
  total_users: number
  users_today: number
  total_qr_scans: number
  today_qr_scans: number
  unique_groups: number
}

export interface Teacher {
  id: number
  name: string
  review_count: number
}

export interface Review {
  id: number
  comment: string
  course: number
  created_at: number
  is_mine: boolean
}

export interface TeacherReviews {
  teacher: Teacher
  reviews: Review[]
}

class ApiClient {
  private webAppUser: any = null

  static getTgUser() {
    const tg = (window as any).Telegram?.WebApp
    return tg?.initData
  }

  setWebAppUser(user: any) {
    this.webAppUser = user
    if (user) {
      localStorage.setItem('telegram_webapp_user', JSON.stringify(user))
    } else {
      localStorage.removeItem('telegram_webapp_user')
    }
  }

  getWebAppUser() {
    if (this.webAppUser) {
      return this.webAppUser
    }
    
    // Try to load from localStorage
    try {
      const stored = localStorage.getItem('telegram_webapp_user')
      if (stored) {
        this.webAppUser = JSON.parse(stored)
        return this.webAppUser
      }
    } catch (error) {
      console.error('Failed to parse stored webAppUser:', error)
      localStorage.removeItem('telegram_webapp_user')
    }
    
    return null
  }

  private getAuthHeaders() {
    return {
      "Content-Type": "application/json",
    }
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
    const url = `${API_BASE_URL}/v1${endpoint}`
    const headers = this.getAuthHeaders()

    // Parse existing body or create new one
    let body: any = {}
    if (options.body) {
      try {
        body = JSON.parse(options.body as string)
      } catch (e) {
        body = {}
      }
    }

    // Add miniAppUser if available (from Telegram WebApp)
    const tgData = ApiClient.getTgUser()
    if (tgData) {
      body.miniAppUser = tgData
    }

    // Add webAppUser if available (from Telegram Widget)
    if (this.webAppUser) {
      body.webAppUser = this.webAppUser
    }

    const response = await fetch(url, {
      ...options,
      headers: {
        ...headers,
        ...options.headers,
      },
      body: JSON.stringify(body),
    })

    if (!response.ok) {
      let errorMessage = `API Error: ${response.status} ${response.statusText}`
      try {
        const errorData = await response.json()
        if (errorData.error) {
          errorMessage = errorData.error
        }
      } catch (e) {
        // Ignore JSON parse errors
      }
      const error = new Error(errorMessage)
      ;(error as any).status = response.status
      throw error
    }

    return response.json()
  }

  async signUp(data: SignUpRequest): Promise<ApiResponse<User>> {
    const body: any = {
      email: data.email,
      password: data.password,
      otp_code: data.otp_code, // <--- ДОБАВЬТЕ ЭТУ СТРОКУ ЗДЕСЬ
    }

    return this.request<User>("/sign-up", {
      method: "POST",
      body: JSON.stringify(body),
    })
  }

  async getCurrentUser(): Promise<ApiResponse<User>> {
    return this.request<User>("/me", {
      method: "POST",
      body: JSON.stringify({}),
    })
  }

  async getDisciplines(): Promise<ApiResponse<DisciplinesResponse>> {
    return this.request<DisciplinesResponse>("/disciplines", {
      method: "POST",
      body: JSON.stringify({}),
    })
  }

  async findStudent(email: string): Promise<ApiResponse<Student>> {
    return this.request<Student>("/find-student", {
      method: "POST",
      body: JSON.stringify({ email }),
    })
  }

  async connectStudent(email: string): Promise<ApiResponse<string>> {
    return this.request<string>("/connect-student", {
      method: "POST",
      body: JSON.stringify({ email }),
    })
  }

  async listConnectedStudents(): Promise<ApiResponse<Student[]>> {
    return this.request<Student[]>("/list-connected-student", {
      method: "POST",
      body: JSON.stringify({}),
    })
  }

  async toggleConnectedStudent(email: string): Promise<ApiResponse<string>> {
    return this.request<string>("/enabled-connected-student", {
      method: "POST",
      body: JSON.stringify({ email }),
    })
  }

  async listConnectedToUser(): Promise<ApiResponse<Student[]>> {
    return this.request<Student[]>("/list-connected-to-user", {
      method: "POST",
      body: JSON.stringify({}),
    })
  }

  async disconnectStudent(email: string): Promise<ApiResponse<string>> {
    return this.request<string>("/disconnect-student", {
      method: "POST",
      body: JSON.stringify({ email }),
    })
  }

  async disconnectFromUser(email: string): Promise<ApiResponse<string>> {
    return this.request<string>("/disconnect-from-user", {
      method: "POST",
      body: JSON.stringify({ email }),
    })
  }

  async scanQr(url: string): Promise<ApiResponse<ScanQrResponse>> {
    return this.request<ScanQrResponse>("/scan-qr", {
      method: "POST",
      body: JSON.stringify({ url }),
    })
  }

  async getBypassStatus(): Promise<ApiResponse<BypassStatus>> {
    return this.request<BypassStatus>("/status-of-bypass", {
      method: "POST",
      body: JSON.stringify({}),
    })
  }

  async getUniversityStatus(): Promise<ApiResponse<UniversityStatus>> {
    return this.request<UniversityStatus>("/university-status", {
      method: "POST",
      body: JSON.stringify({}),
    })
  }

  async getLessons(year: number, month: number, day: number): Promise<ApiResponse<Lesson[]>> {
    return this.request<Lesson[]>("/lessons", {
      method: "POST",
      body: JSON.stringify({ year, month, day }),
    })
  }

  async getAttendance(lessonUuid: string): Promise<ApiResponse<AttendanceRecord[]>> {
    return this.request<AttendanceRecord[]>("/attendance", {
      method: "POST",
      body: JSON.stringify({ lesson_uuid: lessonUuid }),
    })
  }

  async getDeadlines(): Promise<ApiResponse<Deadline[]>> {
    return this.request<Deadline[]>("/deadlines", {
      method: "POST",
      body: JSON.stringify({}),
    })
  }

  async changePassword(data: ChangePasswordRequest): Promise<ApiResponse<string>> {
    return this.request<string>("/change-password", {
      method: "POST",
      body: JSON.stringify(data),
    })
  }

  async updateProxy(data: UpdateProxyRequest): Promise<ApiResponse<string>> {
    return this.request<string>("/update-proxy", {
      method: "POST",
      body: JSON.stringify(data),
    })
  }

  async updateTotpSecret(data: UpdateTotpSecretRequest): Promise<ApiResponse<string>> {
    return this.request<string>("/update-totp-secret", {
      method: "POST",
      body: JSON.stringify(data),
    })
  }

  async deleteUser(): Promise<ApiResponse<string>> {
    return this.request<string>("/delete-user", {
      method: "POST",
      body: JSON.stringify({}),
    })
  }

  async getAdminStats(): Promise<ApiResponse<AdminStats>> {
    return this.request<AdminStats>("/admin/stats", {
      method: "POST",
      body: JSON.stringify({}),
    })
  }

  async searchTeachers(query: string): Promise<ApiResponse<Teacher[]>> {
    return this.request<Teacher[]>("/reviews/search-teacher", {
      method: "POST",
      body: JSON.stringify({ query }),
    })
  }

  async addTeacher(name: string): Promise<ApiResponse<Teacher>> {
    return this.request<Teacher>("/reviews/add-teacher", {
      method: "POST",
      body: JSON.stringify({ name }),
    })
  }

  async getTeacherReviews(teacherId: number): Promise<ApiResponse<TeacherReviews>> {
    return this.request<TeacherReviews>("/reviews/list", {
      method: "POST",
      body: JSON.stringify({ teacher_id: teacherId }),
    })
  }

  async createReview(teacherId: number, comment: string): Promise<ApiResponse<string>> {
    return this.request<string>("/reviews/create", {
      method: "POST",
      body: JSON.stringify({ teacher_id: teacherId, comment }),
    })
  }

  async getAllTeachers(): Promise<ApiResponse<Teacher[]>> {
    return this.request<Teacher[]>("/reviews/teachers", {
      method: "POST",
      body: JSON.stringify({}),
    })
  }

  async deleteReview(teacherId: number): Promise<ApiResponse<string>> {
    return this.request<string>("/reviews/delete", {
      method: "POST",
      body: JSON.stringify({ teacher_id: teacherId }),
    })
  }

  async checkUserRegistration(): Promise<boolean> {
    try {
      // Добавляем таймаут для предотвращения зависания
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 5000) // 5 секунд таймаут
      
      await this.getCurrentUser()
      clearTimeout(timeoutId)
      return true
    } catch (error) {
      console.log("User registration check failed:", error)
      return false
    }
  }
}

export const apiClient = new ApiClient()
